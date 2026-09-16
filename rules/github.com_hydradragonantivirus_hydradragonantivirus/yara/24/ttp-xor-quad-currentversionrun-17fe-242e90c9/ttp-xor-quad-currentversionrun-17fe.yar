rule TTP_XOR_QUAD_CurrentVersionRun_17fe {
  strings:
    $key_17fe = { 44 91 [2] 60 9f [2] 4b b3 [2] 65 91 [2] 71 8a [2] 7e 90 [2] 60 8d [2] 62 8c [2] 79 8a [2] 65 8d [2] 79 a2 }

  condition:
    any of them
}