rule TTP_XOR_QUAD_CurrentVersionRun_3f50 {
  strings:
    $key_3f50 = { 6c 3f [2] 48 31 [2] 63 1d [2] 4d 3f [2] 59 24 [2] 56 3e [2] 48 23 [2] 4a 22 [2] 51 24 [2] 4d 23 [2] 51 0c }

  condition:
    any of them
}