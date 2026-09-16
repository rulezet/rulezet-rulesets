rule TTP_XOR_QUAD_CurrentVersionRun_19fe {
  strings:
    $key_19fe = { 4a 91 [2] 6e 9f [2] 45 b3 [2] 6b 91 [2] 7f 8a [2] 70 90 [2] 6e 8d [2] 6c 8c [2] 77 8a [2] 6b 8d [2] 77 a2 }

  condition:
    any of them
}