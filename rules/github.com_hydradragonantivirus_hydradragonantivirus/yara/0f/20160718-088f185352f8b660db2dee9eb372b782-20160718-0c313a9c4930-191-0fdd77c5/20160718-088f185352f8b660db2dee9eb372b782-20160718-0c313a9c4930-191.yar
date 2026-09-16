rule _20160718_088f185352f8b660db2dee9eb372b782_20160718_0c313a9c4930_191 {
  meta:
    description = "datamaliciousorder - from files 20160718_088f185352f8b660db2dee9eb372b782.js, 20160718_0c313a9c4930528a0cd4c2390bd4b25a.js, 20160718_18bcf6d9b95176c9342003a5bc44456b.js, 20160718_1e067138b76f4766a30940f17e5db7be.js, 20160718_46aea14583e072261e48741ded5c13cb.js, 20160718_65e0e5a087019907c760a698fb705815.js, 20160718_6bf1e0294276279384ee69f02df101a2.js, 20160718_8f2073ae8d8ab93bbe368c77d2580768.js, 20160718_c2bafd3c43efc697bbcd0d60808da2e7.js, 20160718_c3b93eeaaea1078eedc970ed4e329f28.js, 20160718_d67c541aed355f3f5478d2b6941364d6.js, 20160718_f53fbe48128cc919b5d2f2eefc6b25ec.js, 20160718_f58d2dac8740f1d51f8bd281f84b287f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac63731d4787a7c7ad3639c0fcd2696fc9cddc84419a65c60a8317c71899acb8"
    hash2       = "3955512a66d6ffd32493cb31e8615e3fa07f370a831f989b18f4a680dde527ac"
    hash3       = "2a1ad0736f9161489f74d205f9b5eb4a63f1e2521cb3e685478aba023b3dca07"
    hash4       = "a14f481934889a790552f19744ec568bc330b0e6e068f6f76fb4b66b7f914d9e"
    hash5       = "b3796bec479d9e679e4de75103ad2ae7549fadd76a93a2d5fb0ec0b5a3e32f70"
    hash6       = "c6cb02c570fab4f144735dc8b6e720088cd697cebb0b1df717613421a7ef6629"
    hash7       = "5a095a1b5dcc5b1ae83acc47cebf4385227024d3f2ed2644907cf976a99250fc"
    hash8       = "ac08923ae0f3b78ea58a950815ab41ff9e713f7b0ff7b813482f4bbc1935da62"
    hash9       = "4c0ecfbaae23b9df30bc72963abf4f1859a2ad4c49670b3254d4acce7484c348"
    hash10      = "4a11a013f6e27de9d905f72f1c79beb91dcb4d427d111cf50d9b3150438aba69"
    hash11      = "d52f5be4a0131e6a878107427e2e32318a9dfa9cff0ae5adaa26908b49b21529"
    hash12      = "6949c33105e890a7aad3f1f005707c91aeeb0411f59ea56a9e05d4c216b4eba2"
    hash13      = "491483569ccc5bd8af5b847afd55a9465fc9ecca9cdeac0a086aaf62fd6cc3ab"

  strings:
    $s1  = "var shikShikSHAIKERPARTYmaker_PRigund = new Array(-1, -1, -1, -1, -1, -1,-1,-1);" fullword ascii
    $s2  = "if ((!shikShikSHAIKERPARTYmaker_check || !object[shikShikSHAIKERPARTYmaker_property]) && typeof object.prototype[shikShikSHAIKER" ascii
    $s3  = "    return new shikShikSHAIKERPARTYmaker_weirshtrasse(shikShikSHAIKERPARTYmaker_param1.x - shikShikSHAIKERPARTYmaker_param2.x, s" ascii
    $s4  = "if ((!shikShikSHAIKERPARTYmaker_check || !object[shikShikSHAIKERPARTYmaker_property]) && typeof object.prototype[shikShikSHAIKER" ascii
    $s5  = "String.prototype.shikShikSHAIKERPARTYmaker_center4 = function() {" fullword ascii
    $s6  = "String.prototype.shikShikSHAIKERPARTYmaker_center2 = function () {" fullword ascii
    $s7  = "    return new shikShikSHAIKERPARTYmaker_weirshtrasse(shikShikSHAIKERPARTYmaker_param1.x - shikShikSHAIKERPARTYmaker_param2.x, s" ascii
    $s8  = "        } while (shikShikSHAIKERPARTYmaker_i < shikShikSHAIKERPARTYmaker_len && shikShikSHAIKERPARTYmaker_c1 == -1);" fullword ascii
    $s9  = "        } while (shikShikSHAIKERPARTYmaker_i < shikShikSHAIKERPARTYmaker_len && shikShikSHAIKERPARTYmaker_c4 == -1);" fullword ascii
    $s10 = "        } while (shikShikSHAIKERPARTYmaker_i < shikShikSHAIKERPARTYmaker_len && shikShikSHAIKERPARTYmaker_c3 == -1);" fullword ascii
    $s11 = "} catch (shikShikSHAIKERPARTYmaker_RFXuYwO) {WScript.echo(shikShikSHAIKERPARTYmaker_RFXuYwO.message);" fullword ascii
    $s12 = "var shikShikSHAIKERPARTYmaker_dodo = false;" fullword ascii
    $s13 = "function shikShikSHAIKERPARTYmaker_Shtyler4(shikShikSHAIKERPARTYmaker_gutter, shikShikSHAIKERPARTYmaker_StrokaParam2) {" fullword ascii
    $s14 = "};shikShikSHAIKERPARTYmaker_Native.shikShikSHAIKERPARTYmaker_implement = function(shikShikSHAIKERPARTYmaker_objects, shikShikSHA" ascii
    $s15 = "shikShikSHAIKERPARTYmaker_weirshtrasse.shikShikSHAIKERPARTYmaker_subtract = function(shikShikSHAIKERPARTYmaker_param1, shikShikS" ascii
    $s16 = "var shikShikSHAIKERPARTYmaker_pribluda = new Array(" fullword ascii
    $s17 = "shikShikSHAIKERPARTYmaker_TSETZAR = shikShikSHAIKERPARTYmaker_TSETZAR.concat(new Array(-1, -1, -1, -1, -1));" fullword ascii
    $s18 = "shikShikSHAIKERPARTYmaker_weirshtrasse.shikShikSHAIKERPARTYmaker_sameOrN = function(shikShikSHAIKERPARTYmaker_param1, shikShikSH" ascii
    $s19 = " function shikShikSHAIKERPARTYmaker_center(shikShikSHAIKERPARTYmaker_rivulet) {" fullword ascii
    $s20 = "function shikShikSHAIKERPARTYmaker_achievment(shikShikSHAIKERPARTYmaker_bidttt){if(shikShikSHAIKERPARTYmaker_bidttt==1){return 2" ascii

  condition:
    (uint16(0) == 0x0a0d and (8 of them)
    ) or (all of them)
}