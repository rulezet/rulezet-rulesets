rule TTP_XOR_QUAD_CurrentVersionRun_2802 {
  strings:
    $key_2802 = { 7b 6d [2] 5f 63 [2] 74 4f [2] 5a 6d [2] 4e 76 [2] 41 6c [2] 5f 71 [2] 5d 70 [2] 46 76 [2] 5a 71 [2] 46 5e }

  condition:
    any of them
}