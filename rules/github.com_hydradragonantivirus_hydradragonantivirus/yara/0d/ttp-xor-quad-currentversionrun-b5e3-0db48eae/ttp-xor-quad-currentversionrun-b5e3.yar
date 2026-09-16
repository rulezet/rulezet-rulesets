rule TTP_XOR_QUAD_CurrentVersionRun_b5e3 {
  strings:
    $key_b5e3 = { e6 8c [2] c2 82 [2] e9 ae [2] c7 8c [2] d3 97 [2] dc 8d [2] c2 90 [2] c0 91 [2] db 97 [2] c7 90 [2] db bf }

  condition:
    any of them
}