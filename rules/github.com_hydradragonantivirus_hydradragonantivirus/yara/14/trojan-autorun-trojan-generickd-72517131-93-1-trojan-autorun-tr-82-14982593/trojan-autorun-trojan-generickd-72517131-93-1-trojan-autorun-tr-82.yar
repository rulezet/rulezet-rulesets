rule _Trojan_Autorun_Trojan_GenericKD_72517131_93_1_Trojan_Autorun_Tr_82 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKD.72517131_93_1.vir, Trojan.Autorun_Trojan.GenericKD.73131881_1.vir, Trojan.Autorun_Trojan.GenericKDZ.72348_4_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_163_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_260_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_36_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_461_1.vir, Trojan.Autorun_Trojan.GenericKDZ.94847_85_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_157_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_191_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_196_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.uvZ@a8bSq4i.vir, Virus.Hijack_Gen.Trojan.ShellObject.uvZ@a8bSq4i_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.uvZ@a8bSq4i_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.uvZ@a8bSq4i_3.vir, Virus.Hijack_Gen.Trojan.ShellObject.uvZ@a8bSq4i_4.vir, Virus.Hijack_Gen.Trojan.ShellObject.uvZ@a8bSq4i_5.vir, Virus.Hijack_Gen.Trojan.ShellObject.uvZ@a8bSq4i_6.vir, Virus.Hijack_Gen.Trojan.ShellObject.uvZ@a8bSq4i_7.vir, Virus.Hijack_Gen.Trojan.ShellObject.uvZ@a8bSq4i_8.vir, Virus.Hijack_Gen.Trojan.ShellObject.uvZ@a8bSq4i_9.vir, Virus.Hijack_Trojan.Agent.DQQO_386.vir, Virus.Hijack_Trojan.Agent.DQQO_72.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6a357e523ed6bb8fbd373578de488ebe39e700186f4f4ed8a7092be6b13593a"
    hash2       = "dd18c3e61e9b6ecd58a6c4197727ed9fa3520cf7aa34db53cf4bdbacdd3d8858"
    hash3       = "bd6ef55c97c4e362cb909205f130485768fa8aeb0ef4c8bdb812c4744b15ef1d"
    hash4       = "87dfac7d24ffcd868d98b8517074e2c075d4abf43297de31f6bda6587868cb86"
    hash5       = "f08581c2bd3b965fbff6af620026b7b7bb5777c8747f148a829141c2086914a9"
    hash6       = "25fafbd8e6c5444208c8b1f7040fe42be5b06b3aef2cc72547c5e0ab1f4d5f8c"
    hash7       = "78992f1e2f6db49b54f0da45b556e4fcdd5bec85c166b15f8d05857d54794fa8"
    hash8       = "d52e58de8daffa2e44f19d2be01aaddefd1ca50b4ff8a98ffaeaf31d19f4f487"
    hash9       = "ef6b68986f8d138aa37cf07b4b468644aa19a95d9b50b1479e7a43df864281b4"
    hash10      = "a7fe3f930889c77972b5a84f70e3bdb1bb3f6c7be0a2c4042ceb938b64d656ab"
    hash11      = "a84bd1555434c6fa9c1b1be52372035801ad68dd7a3b3200cc2aaded3bac9a96"
    hash12      = "b0df927958b9aeaf098422da0e4938f8a221e0a7d225d56bf22135f2409d4f1d"
    hash13      = "131012a62818ac9451df26b106417d50c9e5928155e5f98708f149b627e7613c"
    hash14      = "914a52725ca277abfaa3463a1537a951b15386dcad369a1c13ad41a170d7ab8c"
    hash15      = "98b689a8f35fe754dc0e93f0db0be48282f56ee4ac8254fad39444cf257c6974"
    hash16      = "7d6746a8fe8fe372ff8789a99297a5e6474bc0d7590f6a5a201aecf3b26b7e6b"
    hash17      = "5c966987e45e753a355d89815c105056abe128e531223911a887ec7ca6d54e3b"
    hash18      = "73f2d456b43a7811133d7ee3a105dce3412eb85f962688b779d2731de3960314"
    hash19      = "bce127fce33727575b85319e7d7654b1121c8900f942af3c760272eec0461670"
    hash20      = "8b3a82caf1a78aefce09af74072dc10f10d3c79f74e5ef386b5332127c2b5d2b"
    hash21      = "f09a4562d8397d3eca707334bbf49c3afc3d74b9c2ad84a14312e5968de9e135"
    hash22      = "11ab6ac03506f57798ef327edfb40aefac5b970d610ac2de5a2d80e147357e33"
    hash23      = "5527428173ae8d80d6972a85a0bc7cd8be51b09ce06b96fc7732c8d84897e690"

  strings:
    $s1  = "Failure in QueryModuleViewModel::ExecuteQuery(). No query has been set" fullword wide
    $s2  = "ClearAndOrNavigate - OnPlaybackLoading callback executed, autoNavigateBehavior={0}, playbackStarted={1}." fullword wide
    $s3  = " - assert(IsBackgroundThread()) failed" fullword wide
    $s4  = "(CurrentHeader.Size.Y - FullyScrolledHeight) < 1 ? 1 : (ScrollViewer.Translation.Y > 0) ? (1 + ScrollViewer.Translation.Y / (Cur" wide
    $s5  = "Clamp(CurrentHeader.TransformMatrix._42 + CurrentHeader.Offset.Y + CurrentHeader.Size.Y - CurrentHeaderProperties.Baseline, 0, C" wide
    $s6  = "Clamp(CurrentHeader.TransformMatrix._42, {0} - Max(ScrollViewer.Translation.Y * OverscrollMultiplier, 0), {1} - Max(ScrollViewer" wide
    $s7  = "Clamp(GroupHeaderProperties.Baseline - CurrentHeader.Offset.Y - HeaderContainer.Size.Y, 0, (NextHeader.Offset.Y > 0 ? NextHeader" wide
    $s8  = "Code error:  Invalid usage of GetCurrentExceptionInfo()" fullword wide
    $s9  = "This operation is not support by CompoundStateTrigger." fullword wide
    $s10 = "Unhandled exception in PlaylistContentItemCommandItemDetails::ChildItem::get" fullword wide
    $s11 = "Invalid media types passed to image loader" fullword wide
    $s12 = "--- {0}: total commit = {1} MB / {2} MB ---" fullword wide
    $s13 = "Buffer Start. ProcessID: " fullword wide
    $s14 = "MetadataProviderHelper::IsMediaDownloadable: Support for ObjectType::Video not implemented yet." fullword wide
    $s15 = "Windows.Foundation.IReferenceArray`1<Windows.Foundation.Collections.IKeyValuePair`2<String, MS.Entertainment.Utilities.SizeBindi" wide
    $s16 = "Windows.Foundation.Collections.IKeyValuePair`2<String, MS.Entertainment.Utilities.SizeBinding>" fullword wide
    $s17 = "Windows.Foundation.Collections.IIterator`1<Windows.Foundation.Collections.IKeyValuePair`2<String, MS.Entertainment.Utilities.Siz" wide
    $s18 = "!!!EXCEPTION NOT HANDLED in ViewModelBase::OnViewInitialized!!!" fullword wide
    $s19 = "!!! Unknown TraceFileSaveSource value !!!" fullword wide
    $s20 = "Failed to find StyleOverride for EmptyErrorStateControl" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}