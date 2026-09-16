rule TTP_XOR_QUAD_CurrentVersionRun_3d31 {
  strings:
    $key_3d31 = { 6e 5e [2] 4a 50 [2] 61 7c [2] 4f 5e [2] 5b 45 [2] 54 5f [2] 4a 42 [2] 48 43 [2] 53 45 [2] 4f 42 [2] 53 6d }

  condition:
    any of them
}