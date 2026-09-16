rule TTP_XOR_QUAD_CurrentVersionRun_3910 {
  strings:
    $key_3910 = { 6a 7f [2] 4e 71 [2] 65 5d [2] 4b 7f [2] 5f 64 [2] 50 7e [2] 4e 63 [2] 4c 62 [2] 57 64 [2] 4b 63 [2] 57 4c }

  condition:
    any of them
}