rule TTP_XOR_QUAD_CurrentVersionRun_2710 {
  strings:
    $key_2710 = { 74 7f [2] 50 71 [2] 7b 5d [2] 55 7f [2] 41 64 [2] 4e 7e [2] 50 63 [2] 52 62 [2] 49 64 [2] 55 63 [2] 49 4c }

  condition:
    any of them
}