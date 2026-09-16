rule TTP_XOR_QUAD_CurrentVersionRun_b512 {
  strings:
    $key_b512 = { e6 7d [2] c2 73 [2] e9 5f [2] c7 7d [2] d3 66 [2] dc 7c [2] c2 61 [2] c0 60 [2] db 66 [2] c7 61 [2] db 4e }

  condition:
    any of them
}