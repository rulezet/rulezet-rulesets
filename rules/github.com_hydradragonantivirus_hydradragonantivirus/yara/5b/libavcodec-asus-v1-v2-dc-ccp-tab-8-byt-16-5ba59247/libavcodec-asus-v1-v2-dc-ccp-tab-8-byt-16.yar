rule libavcodec_asus_v1_v2_dc_ccp_tab__8_byt_16_ {
  strings:
    $a0 = { 01 02 0d 04 0f 04 0c 04 05 03 0e 04 04 03 00 02 }

  condition:
    $a0
}