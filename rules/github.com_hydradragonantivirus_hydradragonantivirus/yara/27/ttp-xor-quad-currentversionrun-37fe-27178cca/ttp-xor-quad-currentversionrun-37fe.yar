rule TTP_XOR_QUAD_CurrentVersionRun_37fe {
  strings:
    $key_37fe = { 64 91 [2] 40 9f [2] 6b b3 [2] 45 91 [2] 51 8a [2] 5e 90 [2] 40 8d [2] 42 8c [2] 59 8a [2] 45 8d [2] 59 a2 }

  condition:
    any of them
}