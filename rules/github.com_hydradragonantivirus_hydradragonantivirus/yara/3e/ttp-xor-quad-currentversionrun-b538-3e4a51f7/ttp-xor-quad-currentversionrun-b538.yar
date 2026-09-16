rule TTP_XOR_QUAD_CurrentVersionRun_b538 {
  strings:
    $key_b538 = { e6 57 [2] c2 59 [2] e9 75 [2] c7 57 [2] d3 4c [2] dc 56 [2] c2 4b [2] c0 4a [2] db 4c [2] c7 4b [2] db 64 }

  condition:
    any of them
}