rule TTP_XOR_QUAD_CurrentVersionRun_6efe {
  strings:
    $key_6efe = { 3d 91 [2] 19 9f [2] 32 b3 [2] 1c 91 [2] 08 8a [2] 07 90 [2] 19 8d [2] 1b 8c [2] 00 8a [2] 1c 8d [2] 00 a2 }

  condition:
    any of them
}