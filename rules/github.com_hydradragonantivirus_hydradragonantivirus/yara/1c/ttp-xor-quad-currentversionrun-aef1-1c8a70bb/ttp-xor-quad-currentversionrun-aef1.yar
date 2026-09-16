rule TTP_XOR_QUAD_CurrentVersionRun_aef1 {
  strings:
    $key_aef1 = { fd 9e [2] d9 90 [2] f2 bc [2] dc 9e [2] c8 85 [2] c7 9f [2] d9 82 [2] db 83 [2] c0 85 [2] dc 82 [2] c0 ad }

  condition:
    any of them
}