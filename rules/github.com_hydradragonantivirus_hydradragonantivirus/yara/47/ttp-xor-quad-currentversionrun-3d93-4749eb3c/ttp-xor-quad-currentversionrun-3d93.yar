rule TTP_XOR_QUAD_CurrentVersionRun_3d93 {
  strings:
    $key_3d93 = { 6e fc [2] 4a f2 [2] 61 de [2] 4f fc [2] 5b e7 [2] 54 fd [2] 4a e0 [2] 48 e1 [2] 53 e7 [2] 4f e0 [2] 53 cf }

  condition:
    any of them
}