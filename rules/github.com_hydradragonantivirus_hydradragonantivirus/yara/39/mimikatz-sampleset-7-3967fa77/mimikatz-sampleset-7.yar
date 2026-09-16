rule Mimikatz_SampleSet_7: APT {
  meta:
    description = "Mimikatz Rule generated from a big Mimikatz sample set"
    author      = "Florian Roth - Florian Roth"
    super_rule  = 1
    hash0       = "821e5dc1ad4bbad2958e036c84bf7734"
    hash1       = "e39e57fb7ff38e7be1a8da785ef83557"
    hash2       = "9ecb8020b0989778009d5aaf13640ea4"
    hash3       = "4bfe2b27a63678fa6b4bd27c8d309508"
    hash4       = "fb164aadc2ae4a7aa3fc3f54cd8fa92a"
    hash5       = "33786d2823e6d5e75b1a3a8bb2837b40"
    hash6       = "a4c1feb5f3f5a71320aeca588cb1f14c"
    hash7       = "36fc962a871cfb9f7d31dc9faaab5b54"
    hash8       = "35bc4af0cbaa48e8a72884e3e690fc3b"
    hash9       = "f1de7a81394efe6cc9438033a75cae0d"
    hash10      = "a6e0cf20f2de5149885297188644f123"
    hash11      = "bb7d4174e9ffae01a14993c528de8653"
    hash12      = "ffd3df1ee7bfd6f1255221c3f82478f1"
    hash13      = "eaf8dfbe80c42dd92740a9e71ea444ab"
    hash14      = "e25b75621c03da7addc55dac378d77c4"
    hash15      = "41ea9b05bcfceca78d51f776bfdee393"
    hash16      = "a03a4272be8a2ee5e48ba2c417ff3b5b"
    hash17      = "96501f7e9dc19a4012b1f5db1dce7018"
    hash18      = "b6fe1b2e961c294155d8f48b6c57f28f"
    hash19      = "1680c6afebcb77a21b6619aedc304931"
    hash20      = "46820c90b2fb296e26b4bb8f7cad51ac"
    hash21      = "a21634571795601f5eace5d503246b3b"
    hash22      = "e6dda29f842ce3b7c72b5536fab4f860"
    hash23      = "006480db3303a7ba9d73e32bc6c0bc11"
    hash24      = "efa68dd73410c4be6f6b0a95a02762f2"
    hash25      = "7194944aa418851631d7e614ff430b0a"
    hash26      = "3a98b9190bf6ed5f75d9c3950a63dd08"
    hash27      = "02f7536279480b73c9942c072c1b5316"
    hash28      = "8638370c805dc92581eba34fa57eb45e"
    hash29      = "6f393ab258b87790a45d6d2b125bbc24"
    hash30      = "dbb01a015ab11266bae5d6381ffd41c2"
    score       = 80

  strings:
    $s0 = "#         * Kernel mode *         #" fullword
    $s1 = "kerberos!KerbGlobalLogonSessionTable" fullword
    $s2 = "Authentication Id : %u ; %u (%08x:%08x)" fullword
    $s3 = "%p - lsasrv!InitializationVector" fullword
    $s4 = "%p - lsasrv!LogonSessionListCount" fullword
    $s7 = "#          * User mode *          #" fullword
    $s8 = "##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )"
    $s9 = "livessp!LiveGlobalLogonSessionList" fullword

  condition:
    all of them
}