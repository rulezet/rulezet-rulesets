rule TTP_XOR_QUAD_CurrentVersionRun_3f40 {
  strings:
    $key_3f40 = { 6c 2f [2] 48 21 [2] 63 0d [2] 4d 2f [2] 59 34 [2] 56 2e [2] 48 33 [2] 4a 32 [2] 51 34 [2] 4d 33 [2] 51 1c }

  condition:
    any of them
}