rule TTP_XOR_QUAD_CurrentVersionRun_fc3d {
  strings:
    $key_fc3d = { af 52 [2] 8b 5c [2] a0 70 [2] 8e 52 [2] 9a 49 [2] 95 53 [2] 8b 4e [2] 89 4f [2] 92 49 [2] 8e 4e [2] 92 61 }

  condition:
    any of them
}