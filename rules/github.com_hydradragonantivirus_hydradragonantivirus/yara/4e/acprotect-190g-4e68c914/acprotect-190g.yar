rule acprotect_190g {
  meta:
    author      = "PEiD"
    description = "ACProtect 1.90g -> Risco software Inc."
    group       = "444"
    function    = "0"

  strings:
    $a0 = { 60 0F 87 02 00 00 00 1B F8 E8 01 00 00 00 73 83 04 24 06 C3 }

  condition:
    $a0
}