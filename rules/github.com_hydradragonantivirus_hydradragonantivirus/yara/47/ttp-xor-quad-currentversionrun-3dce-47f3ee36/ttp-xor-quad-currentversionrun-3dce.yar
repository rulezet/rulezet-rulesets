rule TTP_XOR_QUAD_CurrentVersionRun_3dce {
  strings:
    $key_3dce = { 6e a1 [2] 4a af [2] 61 83 [2] 4f a1 [2] 5b ba [2] 54 a0 [2] 4a bd [2] 48 bc [2] 53 ba [2] 4f bd [2] 53 92 }

  condition:
    any of them
}