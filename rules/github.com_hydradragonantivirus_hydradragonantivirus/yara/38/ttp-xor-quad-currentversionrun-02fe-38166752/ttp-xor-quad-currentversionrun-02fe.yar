rule TTP_XOR_QUAD_CurrentVersionRun_02fe {
  strings:
    $key_02fe = { 51 91 [2] 75 9f [2] 5e b3 [2] 70 91 [2] 64 8a [2] 6b 90 [2] 75 8d [2] 77 8c [2] 6c 8a [2] 70 8d [2] 6c a2 }

  condition:
    any of them
}