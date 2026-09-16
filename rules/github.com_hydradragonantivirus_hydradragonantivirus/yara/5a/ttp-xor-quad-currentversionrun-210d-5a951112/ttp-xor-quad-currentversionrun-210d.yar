rule TTP_XOR_QUAD_CurrentVersionRun_210d {
  strings:
    $key_210d = { 72 62 [2] 56 6c [2] 7d 40 [2] 53 62 [2] 47 79 [2] 48 63 [2] 56 7e [2] 54 7f [2] 4f 79 [2] 53 7e [2] 4f 51 }

  condition:
    any of them
}