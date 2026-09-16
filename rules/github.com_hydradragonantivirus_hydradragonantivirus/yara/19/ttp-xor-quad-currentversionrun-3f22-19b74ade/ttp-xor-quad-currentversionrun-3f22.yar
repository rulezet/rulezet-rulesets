rule TTP_XOR_QUAD_CurrentVersionRun_3f22 {
  strings:
    $key_3f22 = { 6c 4d [2] 48 43 [2] 63 6f [2] 4d 4d [2] 59 56 [2] 56 4c [2] 48 51 [2] 4a 50 [2] 51 56 [2] 4d 51 [2] 51 7e }

  condition:
    any of them
}