rule TTP_XOR_QUAD_CurrentVersionRun_fe81 {
  strings:
    $key_fe81 = { ad ee [2] 89 e0 [2] a2 cc [2] 8c ee [2] 98 f5 [2] 97 ef [2] 89 f2 [2] 8b f3 [2] 90 f5 [2] 8c f2 [2] 90 dd }

  condition:
    any of them
}