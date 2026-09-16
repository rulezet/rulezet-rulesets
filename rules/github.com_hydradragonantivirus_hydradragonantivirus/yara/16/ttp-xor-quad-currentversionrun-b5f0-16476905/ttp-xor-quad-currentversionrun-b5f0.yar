rule TTP_XOR_QUAD_CurrentVersionRun_b5f0 {
  strings:
    $key_b5f0 = { e6 9f [2] c2 91 [2] e9 bd [2] c7 9f [2] d3 84 [2] dc 9e [2] c2 83 [2] c0 82 [2] db 84 [2] c7 83 [2] db ac }

  condition:
    any of them
}