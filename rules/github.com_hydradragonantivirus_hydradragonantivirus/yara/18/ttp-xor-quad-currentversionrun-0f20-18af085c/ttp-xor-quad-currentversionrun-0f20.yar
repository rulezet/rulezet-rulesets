rule TTP_XOR_QUAD_CurrentVersionRun_0f20 {
  strings:
    $key_0f20 = { 5c 4f [2] 78 41 [2] 53 6d [2] 7d 4f [2] 69 54 [2] 66 4e [2] 78 53 [2] 7a 52 [2] 61 54 [2] 7d 53 [2] 61 7c }

  condition:
    any of them
}