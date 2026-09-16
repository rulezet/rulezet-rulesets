rule TTP_XOR_QUAD_CurrentVersionRun_2310 {
  strings:
    $key_2310 = { 70 7f [2] 54 71 [2] 7f 5d [2] 51 7f [2] 45 64 [2] 4a 7e [2] 54 63 [2] 56 62 [2] 4d 64 [2] 51 63 [2] 4d 4c }

  condition:
    any of them
}