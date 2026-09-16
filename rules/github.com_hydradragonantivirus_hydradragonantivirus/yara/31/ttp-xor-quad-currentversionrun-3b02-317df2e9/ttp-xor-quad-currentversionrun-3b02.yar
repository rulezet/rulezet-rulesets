rule TTP_XOR_QUAD_CurrentVersionRun_3b02 {
  strings:
    $key_3b02 = { 68 6d [2] 4c 63 [2] 67 4f [2] 49 6d [2] 5d 76 [2] 52 6c [2] 4c 71 [2] 4e 70 [2] 55 76 [2] 49 71 [2] 55 5e }

  condition:
    any of them
}