rule TTP_XOR_QUAD_CurrentVersionRun_1a32 {
  strings:
    $key_1a32 = { 49 5d [2] 6d 53 [2] 46 7f [2] 68 5d [2] 7c 46 [2] 73 5c [2] 6d 41 [2] 6f 40 [2] 74 46 [2] 68 41 [2] 74 6e }

  condition:
    any of them
}