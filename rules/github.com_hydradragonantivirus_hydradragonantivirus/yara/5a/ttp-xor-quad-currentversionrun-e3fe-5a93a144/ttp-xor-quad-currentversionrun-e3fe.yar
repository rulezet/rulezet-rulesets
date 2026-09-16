rule TTP_XOR_QUAD_CurrentVersionRun_e3fe {
  strings:
    $key_e3fe = { b0 91 [2] 94 9f [2] bf b3 [2] 91 91 [2] 85 8a [2] 8a 90 [2] 94 8d [2] 96 8c [2] 8d 8a [2] 91 8d [2] 8d a2 }

  condition:
    any of them
}