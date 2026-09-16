rule TTP_XOR_QUAD_CurrentVersionRun_e6fe {
  strings:
    $key_e6fe = { b5 91 [2] 91 9f [2] ba b3 [2] 94 91 [2] 80 8a [2] 8f 90 [2] 91 8d [2] 93 8c [2] 88 8a [2] 94 8d [2] 88 a2 }

  condition:
    any of them
}