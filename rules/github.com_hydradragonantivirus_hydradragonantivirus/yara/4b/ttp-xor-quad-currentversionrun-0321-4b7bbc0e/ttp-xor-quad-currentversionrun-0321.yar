rule TTP_XOR_QUAD_CurrentVersionRun_0321 {
  strings:
    $key_0321 = { 50 4e [2] 74 40 [2] 5f 6c [2] 71 4e [2] 65 55 [2] 6a 4f [2] 74 52 [2] 76 53 [2] 6d 55 [2] 71 52 [2] 6d 7d }

  condition:
    any of them
}