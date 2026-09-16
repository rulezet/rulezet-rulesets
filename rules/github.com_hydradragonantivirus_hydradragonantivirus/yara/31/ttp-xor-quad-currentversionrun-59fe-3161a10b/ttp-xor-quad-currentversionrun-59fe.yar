rule TTP_XOR_QUAD_CurrentVersionRun_59fe {
  strings:
    $key_59fe = { 0a 91 [2] 2e 9f [2] 05 b3 [2] 2b 91 [2] 3f 8a [2] 30 90 [2] 2e 8d [2] 2c 8c [2] 37 8a [2] 2b 8d [2] 37 a2 }

  condition:
    any of them
}