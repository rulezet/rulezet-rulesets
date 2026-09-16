rule o231b_4b9c6a48c0000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o231b.4b9c6a48c0000b12"
    cluster         = "o231b.4b9c6a48c0000b12"
    cluster_size    = "43"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "cryxos coinminer miner"
    md5_hashes      = "['0a43037cc8fbaac3a68f30baa0769a076b9b12f5','8ebacf7713a64607201f0ebe52d70f5dc4028c68','614325bde4d938359839ceb4ca1ad0ab12eae9c4']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o231b.4b9c6a48c0000b12"

  strings:
    $hex_string = "class=\"ajax-loader\"></span>' );\n\n\t\twpcf7.toggleSubmit( $form );\n"

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}