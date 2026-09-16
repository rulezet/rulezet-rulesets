rule TTP_XOR_QUAD_CurrentVersionRun_4efe {
  strings:
    $key_4efe = { 1d 91 [2] 39 9f [2] 12 b3 [2] 3c 91 [2] 28 8a [2] 27 90 [2] 39 8d [2] 3b 8c [2] 20 8a [2] 3c 8d [2] 20 a2 }

  condition:
    any of them
}