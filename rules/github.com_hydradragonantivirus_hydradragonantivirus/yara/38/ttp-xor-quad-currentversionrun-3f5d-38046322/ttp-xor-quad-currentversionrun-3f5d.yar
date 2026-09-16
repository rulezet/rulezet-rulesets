rule TTP_XOR_QUAD_CurrentVersionRun_3f5d {
  strings:
    $key_3f5d = { 6c 32 [2] 48 3c [2] 63 10 [2] 4d 32 [2] 59 29 [2] 56 33 [2] 48 2e [2] 4a 2f [2] 51 29 [2] 4d 2e [2] 51 01 }

  condition:
    any of them
}