rule TTP_XOR_QUAD_CurrentVersionRun_b522 {
  strings:
    $key_b522 = { e6 4d [2] c2 43 [2] e9 6f [2] c7 4d [2] d3 56 [2] dc 4c [2] c2 51 [2] c0 50 [2] db 56 [2] c7 51 [2] db 7e }

  condition:
    any of them
}