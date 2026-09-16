rule TTP_XOR_QUAD_CurrentVersionRun_21fe {
  strings:
    $key_21fe = { 72 91 [2] 56 9f [2] 7d b3 [2] 53 91 [2] 47 8a [2] 48 90 [2] 56 8d [2] 54 8c [2] 4f 8a [2] 53 8d [2] 4f a2 }

  condition:
    any of them
}