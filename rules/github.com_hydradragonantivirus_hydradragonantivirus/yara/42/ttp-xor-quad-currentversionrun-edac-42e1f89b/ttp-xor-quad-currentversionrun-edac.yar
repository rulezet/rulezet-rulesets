rule TTP_XOR_QUAD_CurrentVersionRun_edac {
  strings:
    $key_edac = { be c3 [2] 9a cd [2] b1 e1 [2] 9f c3 [2] 8b d8 [2] 84 c2 [2] 9a df [2] 98 de [2] 83 d8 [2] 9f df [2] 83 f0 }

  condition:
    any of them
}