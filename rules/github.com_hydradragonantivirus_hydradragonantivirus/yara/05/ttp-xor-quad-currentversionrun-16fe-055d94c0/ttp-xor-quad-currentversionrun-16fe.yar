rule TTP_XOR_QUAD_CurrentVersionRun_16fe {
  strings:
    $key_16fe = { 45 91 [2] 61 9f [2] 4a b3 [2] 64 91 [2] 70 8a [2] 7f 90 [2] 61 8d [2] 63 8c [2] 78 8a [2] 64 8d [2] 78 a2 }

  condition:
    any of them
}