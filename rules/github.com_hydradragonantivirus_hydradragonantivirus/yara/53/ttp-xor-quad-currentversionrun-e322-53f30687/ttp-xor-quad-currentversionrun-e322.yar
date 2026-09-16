rule TTP_XOR_QUAD_CurrentVersionRun_e322 {
  strings:
    $key_e322 = { b0 4d [2] 94 43 [2] bf 6f [2] 91 4d [2] 85 56 [2] 8a 4c [2] 94 51 [2] 96 50 [2] 8d 56 [2] 91 51 [2] 8d 7e }

  condition:
    any of them
}