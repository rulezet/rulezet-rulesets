rule TTP_XOR_QUAD_CurrentVersionRun_212e {
  strings:
    $key_212e = { 72 41 [2] 56 4f [2] 7d 63 [2] 53 41 [2] 47 5a [2] 48 40 [2] 56 5d [2] 54 5c [2] 4f 5a [2] 53 5d [2] 4f 72 }

  condition:
    any of them
}