rule TTP_XOR_QUAD_CurrentVersionRun_f7fe {
  strings:
    $key_f7fe = { a4 91 [2] 80 9f [2] ab b3 [2] 85 91 [2] 91 8a [2] 9e 90 [2] 80 8d [2] 82 8c [2] 99 8a [2] 85 8d [2] 99 a2 }

  condition:
    any of them
}