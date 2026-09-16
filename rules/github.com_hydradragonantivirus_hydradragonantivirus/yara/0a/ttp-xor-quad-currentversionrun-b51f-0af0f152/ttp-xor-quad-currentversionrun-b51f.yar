rule TTP_XOR_QUAD_CurrentVersionRun_b51f {
  strings:
    $key_b51f = { e6 70 [2] c2 7e [2] e9 52 [2] c7 70 [2] d3 6b [2] dc 71 [2] c2 6c [2] c0 6d [2] db 6b [2] c7 6c [2] db 43 }

  condition:
    any of them
}