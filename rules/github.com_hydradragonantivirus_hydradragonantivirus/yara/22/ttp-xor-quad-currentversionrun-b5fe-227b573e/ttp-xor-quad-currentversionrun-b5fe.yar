rule TTP_XOR_QUAD_CurrentVersionRun_b5fe {
  strings:
    $key_b5fe = { e6 91 [2] c2 9f [2] e9 b3 [2] c7 91 [2] d3 8a [2] dc 90 [2] c2 8d [2] c0 8c [2] db 8a [2] c7 8d [2] db a2 }

  condition:
    any of them
}