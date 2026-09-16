rule TTP_XOR_QUAD_CurrentVersionRun_e7fe {
  strings:
    $key_e7fe = { b4 91 [2] 90 9f [2] bb b3 [2] 95 91 [2] 81 8a [2] 8e 90 [2] 90 8d [2] 92 8c [2] 89 8a [2] 95 8d [2] 89 a2 }

  condition:
    any of them
}