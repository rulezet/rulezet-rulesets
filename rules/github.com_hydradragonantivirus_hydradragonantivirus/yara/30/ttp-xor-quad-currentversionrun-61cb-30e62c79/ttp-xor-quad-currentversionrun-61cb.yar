rule TTP_XOR_QUAD_CurrentVersionRun_61cb {
  strings:
    $key_61cb = { 32 a4 [2] 16 aa [2] 3d 86 [2] 13 a4 [2] 07 bf [2] 08 a5 [2] 16 b8 [2] 14 b9 [2] 0f bf [2] 13 b8 [2] 0f 97 }

  condition:
    any of them
}