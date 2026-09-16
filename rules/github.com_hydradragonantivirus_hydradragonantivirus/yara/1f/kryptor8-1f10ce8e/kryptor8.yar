rule kryptor8 {
  meta:
    author      = "PEiD"
    description = "k.kryptor 8 -> r!sc & noodlespa"
    group       = "128"
    function    = "0"

  strings:
    $a0 = { EB 6A 87 DB }

  condition:
    $a0
}