rule TTP_XOR_QUAD_CurrentVersionRun_f1fe {
  strings:
    $key_f1fe = { a2 91 [2] 86 9f [2] ad b3 [2] 83 91 [2] 97 8a [2] 98 90 [2] 86 8d [2] 84 8c [2] 9f 8a [2] 83 8d [2] 9f a2 }

  condition:
    any of them
}