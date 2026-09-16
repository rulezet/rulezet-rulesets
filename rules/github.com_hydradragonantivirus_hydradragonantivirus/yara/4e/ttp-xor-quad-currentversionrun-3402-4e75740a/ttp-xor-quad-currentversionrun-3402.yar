rule TTP_XOR_QUAD_CurrentVersionRun_3402 {
  strings:
    $key_3402 = { 67 6d [2] 43 63 [2] 68 4f [2] 46 6d [2] 52 76 [2] 5d 6c [2] 43 71 [2] 41 70 [2] 5a 76 [2] 46 71 [2] 5a 5e }

  condition:
    any of them
}