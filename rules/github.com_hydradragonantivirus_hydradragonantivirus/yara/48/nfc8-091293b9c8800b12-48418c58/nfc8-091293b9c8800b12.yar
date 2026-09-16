rule nfc8_091293b9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=nfc8.091293b9c8800b12"
    cluster         = "nfc8.091293b9c8800b12"
    cluster_size    = "10"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "cryxos banker androidos"
    md5_hashes      = "['0ea44063a3dee4a90cdae6a6b8d282cc3d1299fe','86a890f2bf1bd3bbfef611d494e16dd4168d2084','c7068e2a9204c4933fe5d0c5775331b3c27d9ff0']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=nfc8.091293b9c8800b12"

  strings:
    $hex_string = { eb a7 31 86 6b 09 ae d5 a3 28 30 e5 25 6f c1 c4 bb 38 74 d0 1b 33 9f 7b f9 45 a5 92 f1 1a b7 fb 89 32 f7 1c bf a2 ad 14 d7 9d 13 67 83 d8 c5 c6 12 c8 71 07 e6 66 65 4c 16 f4 99 22 f3 cd 8a 87 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}