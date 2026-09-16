rule tree3 {
  strings:
    $s0    = "NSUndoManagerProxy" fullword
    $s1    = "ZTSN5boost18thread" fullword
    $s2    = "sSS10FoundationE4data8encodingSSSgAA4DataVh" fullword
    $s3    = "NSAutoreleasePool" fullword
    $s4    = "IOCreatePlugInInterfaceForService" fullword
    $s5    = "setLargeTitleTextAttributes" fullword
    $s6    = "getAuthorization" fullword
    $s7    = "isLifetimeEnabled" fullword
    $s8    = "restoreUIStateFromDictionary" fullword
    $s9    = "ZN5xmrig9Arguments3addEPKc" fullword
    $s10   = "getCursorPosition" fullword
    $s11   = "willChangeStatusBarOrientation" fullword
    $s12   = "ZBNetworkReachability" fullword
    $s13   = "140129192647Z0A1" fullword
    $s14   = "logKextUserClient" fullword
    $s15   = "EHMHMHMHMHMHMHMHMHMHMH" fullword
    $s16   = "ZBSystemInformation" fullword
    $s17   = "krStringWithUUID" fullword
    $s18   = "E6targetERKSt9type" fullword
    $s19   = "UHAWAVAUATSHHLMLEHMHLe" fullword
    $s20   = "NetworkExtension" fullword
    $s21   = "certificateauthority0" fullword
    $s23   = "CFBundleShortVersionString" fullword
    $s24   = "getImplementation" fullword
    $s25   = "efCkKaADK3CAKRCNC" fullword
    $s26   = "loadWeakRetained" fullword
    $s27   = "DEDEDEDEDEDEDEDE9E" fullword
    $s28   = "sqhIJsyyeFaPcYe7" fullword
    $s29   = "launchJavaApplication" fullword
    $s30   = "previousblockhash" fullword
    $s31   = "iPhoneSimulator10" fullword
    $s32   = "SystemConfiguration" fullword
    $s33   = "invalidateShadow" fullword
    $s34   = "setCanChooseDirectories" fullword
    $s35   = "CFStringMakeConstantString" fullword
    $s36   = "HMHMHMHMHMHMHMHMHMH" fullword
    $s37   = "initWithSuiteName" fullword
    $s39   = "libswiftCoreGraphics" fullword
    $s40   = "UHAWAVAUATSH8LMHMHUHuHH" fullword
    $s41   = "numberWithUnsignedInt" fullword
    $s42   = "stringWithUTF8String" fullword
    $s43   = "FromStringAndSize" fullword
    $s44   = "connectionDidFinishLoading" fullword
    $s45   = "terminationStatus" fullword
    $s46   = "HEHEHEHEHEHEHEHEHEHEHE" fullword
    $s47   = "UHAWAVAUATSHHHuE" fullword
    $s48   = "spDkrKTDKFCLC8CXD" fullword
    $s49   = "UHAWAVAUATSPEAIHIHtXH" fullword
    $s50   = "didUpdateUserActivity" fullword
    $s51   = "ZBLocalizationContext" fullword
    $s52   = "20160507105842Z0" fullword
    $s53   = "HuHUHEHHMHMHMHMHUHuHHuHHUH" fullword
    $s55   = "certificateauthority" fullword
    $s56   = "CFArrayGetValueAtIndex" fullword
    $s57   = "conformsToProtocol" fullword
    $s58   = "ddddddddddddddddddddddddddddddddsd" fullword
    $s59   = "e4zPO0A75QibEoIM1dS3ccGV3ag" fullword
    $s60   = "isAppStoreDistribution" fullword
    $s61   = "UHAWAVAUATSHhDMLpHMHUHuE" fullword
    $s62   = "140213191008Z0A1" fullword
    $s63   = "dictionaryWithContentsOfFile" fullword
    $s64   = "autoreleasePoolPop" fullword
    $s65   = "setIsAccessibilityElement" fullword
    $s66   = "PrivateFrameworks" fullword
    $s67   = "ZN9QListData11shared" fullword
    $s68   = "abcdefghijklmnopqrstuvwxyz" fullword
    $s69   = "270201221215Z0y1" fullword
    $s70   = "kCFAllocatorDefault" fullword
    $s71   = "copyElephantBrain" fullword
    $s72   = "componentsSeparatedByString" fullword
    $s73   = "stringWithFormat" fullword
    $s74   = "initWithCapacity" fullword
    $s75   = "ApplicationServices" fullword
    $s76   = "retainAutoreleasedReturnValue" fullword
    $s77   = "CFConstantStringClassReference" fullword
    $s78   = "HMHMHMHMHMHMHMHML" fullword
    $s80   = "ZTSN5boost9exceptionE" fullword
    $s81   = "IOServiceGetMatchingServices" fullword
    $s82   = "ZN7QObject10childEventEP11QChildEvent" fullword
    $s83   = "retainAutorelease" fullword
    $s84   = "certificationauthority" fullword
    $s85   = "DefaultRuneLocale" fullword
    $s86   = "MobileCoreServices" fullword
    $s87   = "350209214036Z0b1" fullword
    $s88   = "NSStringFromClass" fullword
    $s89   = "localizedStringForKey" fullword
    $s90   = "OSAtomicDecrement32" fullword
    $s91   = "NSAddressOfSymbol" fullword
    $s94   = "UHAWAVAUATSH8IIH" fullword
    $s95   = "9allocatorIcEEEE" fullword
    $s96   = "UHAWAVAUATSPIIID" fullword
    $s97   = "lswiftObjectiveC" fullword
    $s98   = "ServiceManagement" fullword
    $s99   = "retainAutoreleaseReturnValue" fullword
    $s100  = "libswiftDispatch" fullword
    $s101  = "debugDescription" fullword
    $s104  = "x2fvpr854319l6k9d06xlwt0rqm9vf" fullword
    $s134  = "CFStringGetCString" fullword
    $s135  = "9allocatorIcEEEC1ERKS5" fullword
    $s138  = "JSObjectSetProperty" fullword
    $s142  = "respondsToSelector" fullword
    $s144  = "UHAWAVAUATSPAAII" fullword
    $s145  = "ecpointformatlist" fullword
    $s147  = "NSConcreteGlobalBlock" fullword
    $s148  = "contentsOfDirectoryAtPath" fullword
    $s149  = "fileExistsAtPath" fullword
    $s150  = "arrayWithObjects" fullword
    $s151  = "isAccessibilityElement" fullword
    $s152  = "isItemExpandable" fullword
    $s153  = "HMHMHMHMHMHMHMHMH" fullword
    $s154  = "0123456789abcdef" fullword
    $s155  = "dataUsingEncoding" fullword
    $s156  = "NSFilenamesPboardType" fullword
    $s157  = "traitsIcEEE3putEc" fullword
    $s158  = "enumerationMutation" fullword
    $s159  = "replaceCharactersInRange" fullword
    $s162  = "UHAWAVAUATSH8IHH" fullword
    $s168  = "NSNotificationCenter" fullword
    $s190  = "UIViewController" fullword
    $s191  = "SecItemCopyMatching" fullword
    $s254  = "countByEnumeratingWithState" fullword
    $s257  = "191128154500Z0A1" fullword
    $s260  = "IntermediateBuildFilesPath" fullword
    $s261  = "CFBundleIdentifier" fullword
    $s262  = "9allocatorIcEEE6insertEmPKcm" fullword
    $s264  = "AuthorizationFree" fullword
    $s265  = "CFStringCreateWithCString" fullword
    $s269  = "200219223002Z0B1" fullword
    $s275  = "180123004003Z0A1" fullword
    $s386  = "UserNotifications" fullword
    $s389  = "autoreleaseReturnValue" fullword
    $s426  = "CFBundleCopyBundleURL" fullword
    $s436  = "applicationDockMenu" fullword
    $s438  = "NSDistributedNotificationCenter" fullword
    $s442  = "isYahooSearchURL" fullword
    $s446  = "UHAWAVAUATSHxMLEUuAH" fullword
    $s448  = "getblocktemplate" fullword
    $s449  = "k7kBkQkpkkkkkkkkkkflmllllll" fullword
    $s450  = "ZNK2cv3Mat5MStepixEi" fullword
    $s452  = "errcallEPPFvPK5DbEnvPKcS4" fullword
    $s453  = "GCCopyAppDataDir" fullword
    $s455  = "ponponqqtsrtsruuxwvwvyy" fullword
    $s456  = "removeCustomView" fullword
    $s458  = "EqualizationPhase1" fullword
    $s459  = "setInnvcx4sqaCHC" fullword
    $s460  = "crossCertificatePair" fullword
    $s461  = "20191105000000Z0" fullword
    $s462  = "NSAssertionHandler" fullword
    $s463  = "ZN6Common9JsonValue3setERKNSt3" fullword
    $s464  = "0x66AAEE44446688AAUL" fullword
    $s465  = "arrayWithCapacity" fullword
    $s468  = "140305162647Z0A1" fullword
    $s470  = "s8Dispatch0A4TimeVMa" fullword
    $s473  = "redirectResponse" fullword
    $s477  = "category23default" fullword
    $s479  = "GenerateConnectionID" fullword
    $s480  = "applicationWillHide" fullword
    $s483  = "DisableThreadLibraryCalls" fullword
    $s484  = "fHSUATAUAVIHHIHIHD" fullword
    $s485  = "IOConnectMapMemory" fullword
    $s486  = "stringCompareWithSmolCheck" fullword
    $s489  = "ellipticcurvelist" fullword
    $s492  = "selectorPFP11objc" fullword
    $s494  = "UHAWAVAUATSH8IIHH" fullword
    $s495  = "UHAWAVAUATSPIHIH" fullword
    $s497  = "191127221001Z0A1" fullword
    $s507  = "N5boost9exceptionE" fullword
    $s511  = "reachabilityWithHostName" fullword
    $s512  = "USBInterfaceOpen" fullword
    $s518  = "getExistentialTypeMetadata" fullword
    $s523  = "NSFetchedPropertyDescription" fullword
    $s559  = "20191001103003Z0" fullword
    $s579  = "CFBundleCopyResourceURL" fullword
    $s582  = "encodeURIComponent" fullword
    $s586  = "mediumspringgreen" fullword
    $s588  = "bundleIdentifier" fullword
    $s589  = "traitsIcEEE5tellgEv" fullword
    $s590  = "shouldHighlightRowAtIndexPath" fullword
    $s603  = "ZNK12QMapNodeBase8nextNodeEv" fullword
    $s604  = "UHAWAVAUATSHHMIIM" fullword
    $s606  = "clickedButtonAtIndex" fullword
    $s607  = "HEHEHEHEHEHEHEHE" fullword
    $s609  = "objectAtIndexedSubscript" fullword
    $s617  = "ZN9QListData7disposeEPNS" fullword
    $s619  = "UHAWAVAUATSPIHIIH" fullword
    $s620  = "CommitTransaction" fullword
    $s626  = "alSourceQueueBuffers" fullword
    $s634  = "glFramebufferTextureLayer" fullword
    $s637  = "StringCharCodeAt" fullword
    $s638  = "UHAWAVAUATSH8HIH" fullword
    $s714  = "unzGoToFilePos64" fullword
    $s753  = "UHAWAVAUATSPILuI" fullword
    $s762  = "constructInstance" fullword
    $s807  = "5streqELb1EEENS7" fullword
    $s808  = "CFURLCopyFileSystemPath" fullword
    $s812  = "3protectExecutableMemoryEPvm" fullword
    $s823  = "CGContextFillRect" fullword
    $s825  = "operatingSystemVersionString" fullword
    $s846  = "CFDictionaryCreateMutable" fullword
    $s848  = "IORegistryEntryCreateCFProperty" fullword
    $s851  = "sharedApplication" fullword
    $s865  = "withIntermediateDirectories" fullword
    $s868  = "numberWithUnsignedInteger" fullword
    $s870  = "traitsIcEEE9showmanycEv" fullword
    $s871  = "CFNumberGetValue" fullword
    $s883  = "IOPlatformExpertDevice" fullword
    $s888  = "traitsIcEEEEE16find" fullword
    $s891  = "DqGCHHHVMoNMoPQS" fullword
    $s918  = "deletedMethodError" fullword
    $s925  = "stringByAppendingPathComponent" fullword
    $s927  = "completionHandler" fullword
    $s931  = "Z83Z8CZ8SZ8cZ8sZ8z" fullword
    $s932  = "Z83Z8CZ8SZ8cZ8sZ8" fullword
    $s969  = "connectionRequired" fullword
    $s971  = "enumerateKeysAndObjectsUsingBlock" fullword
    $s975  = "assertionFailure" fullword
    $s999  = "ZN9QListData6appendERKS" fullword
    $s1018 = "N5boost6detail11thread" fullword
    $s1020 = "ZN7QLayout18setContentsMarginsEiiii" fullword
    $s1036 = "substringToIndex" fullword
    $s1038 = "ZBSafeConnectionRootProxyStateDidChangeNotification" fullword
    $s1043 = "setStandardOutput" fullword
    $s1050 = "CFRunLoopGetMain" fullword
    $s1052 = "AssemblyProductAttribute" fullword
    $s1073 = "Z83Z8CZ8SZ8cZ8sZ82" fullword
    $s1099 = "didFinishLoadingNavigation" fullword
    $s1100 = "NSOperationQueue" fullword
    $s1103 = "setTimeoutIntervalForResource" fullword
    $s1104 = "UIModalPresentationOverCurrentContext" fullword
    $s1110 = "CSo12NSDictionary" fullword
    $s1112 = "viewForHeaderInSection" fullword
    $s1121 = "NSJSONSerialization" fullword
    $s1131 = "UBRARARARARARARARARARARARARARARARARARARBRB" fullword
    $s1142 = "IORegistryEntryGetParentEntry" fullword
    $s1151 = "LSSharedFileListItemSetProperty" fullword
    $s1152 = "addScriptMessageHandler" fullword
    $s1153 = "fileHandleForReading" fullword
    $s1154 = "removeScannedItem" fullword
    $s1155 = "labelUnconfirmed" fullword
    $s1156 = "welcomeScreenIdentifier" fullword
    $s1157 = "libswiftCoreFoundation" fullword
    $s1159 = "ZBInvocationOperation" fullword
    $s1160 = "ZBInstallationInfo" fullword
    $s1161 = "kNECDeviceDetailsOSVersionKey" fullword
    $s1163 = "generationComplete" fullword
    $s1164 = "introductionView" fullword
    $s1165 = "stopStatusIconAnimation" fullword
    $s1166 = "webScriptNameForSelector" fullword
    $s1167 = "showPageWithIndex" fullword
    $s1168 = "navigationBarNodeSortingOrder" fullword
    $s1173 = "ZBAgentDidChangeNotification" fullword
    $s1187 = "columnIndexForName" fullword
    $s1192 = "resignFirstResponder" fullword
    $s1193 = "sizeOfItemAtPath" fullword
    $s1197 = "newVersionAvailable" fullword
    $s1198 = "ZN2cv10AutoBufferIhLm4104EE8allocateEm" fullword
    $s1205 = "GetDiskFreeSpace" fullword
    $s1208 = "getInstanceMethod" fullword
    $s1221 = "dataWithContentsOfFile" fullword
    $s1225 = "numberWithUnsignedLong" fullword
    $s1226 = "ZTIN10CryptoNote24JsonInputValueSerializerE" fullword
    $s1239 = "timeIntervalSinceDate" fullword
    $s1253 = "NSMutableURLRequest" fullword
    $s1262 = "enumerateObjectsUsingBlock" fullword
    $s1272 = "NSURLSessionDataDelegate" fullword
    $s1276 = "didFailToContinueUserActivityWithType" fullword
    $s1279 = "kSecAttrAccessibleWhenUnlockedThisDeviceOnly" fullword
    $s1282 = "applicationWillUnhide" fullword
    $s1292 = "initWithContentsOfURL" fullword
    $s1294 = "NSMutableOrderedSet" fullword
    $s1307 = "titleForDeleteConfirmationButtonForRowAtIndexPath" fullword
    $s1321 = "createFileAtPath" fullword
    $s1327 = "dictionaryWithJSONString" fullword
    $s1330 = "uriuwfgjZasjXjjgZm" fullword
    $s1332 = "systemFontOfSize" fullword
    $s1336 = "NSPropertyListSerialization" fullword
    $s1338 = "CGContextRelease" fullword
    $s1358 = "setStandardInput" fullword
    $s1379 = "componentsJoinedByString" fullword
    $s1380 = "setAttributedTitle" fullword
    $s1386 = "commitPreviewingViewController" fullword
    $s1396 = "removeObjectForKey" fullword
    $s1397 = "didFailToRegisterForRemoteNotificationsWithError" fullword
    $s1398 = "sSo18NSFileAttributeKeyaSHSCSH13" fullword
    $s1405 = "replaceObjectAtIndex" fullword
    $s1408 = "11checkObjectERKNSt3" fullword
    $s1411 = "15mutex6unlockEv" fullword
    $s1413 = "N5boost9gregorian15bad" fullword
    $s1432 = "ZNK5boost13match" fullword
    $s1435 = "ZZ16SelectBaseParamsN16CBaseChainParams7NetworkEE8" fullword
    $s1446 = "characterIsMember" fullword
    $s1448 = "authenticationPolicy" fullword
    $s1450 = "UHAWAVAUATSH8HLg" fullword
    $s1451 = "So6CGRectVSStcfc" fullword
    $s1453 = "setProgressThreadSafe" fullword
    $s1454 = "UHAWAVATSIII1Mt2Mt" fullword
    $s1461 = "fastIndexForKnownKey" fullword
    $s1462 = "DRGp0SARARARARARA" fullword
    $s1468 = "continueUserActivity" fullword
    $s1473 = "ZL12cxxConstructP11objc" fullword
    $s1488 = "forKeyedSubscriptP19NSMutableDictionaryP13objc" fullword
    $s1490 = "downloadTaskWithResumeData" fullword
    $s1491 = "SecStaticCodeCreateWithPath" fullword
    $s1493 = "lockScreenAuthenticationDidFailWithAttempt" fullword
    $s1499 = "ZL30NSUndoManagerProxy" fullword
    $s1502 = "conformsToProtocolEPKNS" fullword
    $s1513 = "kZBZeoAccountLoggedOutNotification" fullword
    $s1520 = "RGp0SARARARARARA" fullword
    $s1546 = "ZBULocalizationContext" fullword
    $s1552 = "URLSessionDidFinishEventsForBackgroundURLSession" fullword
    $s1559 = "kZBIdentifierKey" fullword
    $s1560 = "RARARARARARARARARARAZAp" fullword
    $s1568 = "didPresentAlertView" fullword
    $s1571 = "applicationDidUnhide" fullword
    $s1572 = "makeNewConnection" fullword
    $s1573 = "dataWithJSONObject" fullword
    $s1591 = "viewForTableColumn" fullword
    $s1594 = "ZL19transcribeProtocolsP10objc" fullword
    $s1601 = "DispatchOnceCounter" fullword
    $s1602 = "SCNetworkReachabilityUnscheduleFromRunLoop" fullword
    $s1611 = "NSRunningApplication" fullword
    $s1612 = "createDirectoryAtURL" fullword
    $s1613 = "copyClassNamesForImage" fullword
    $s1619 = "autoreleasepoolPK11mach" fullword
    $s1623 = "totalBytesExpectedToSend" fullword
    $s1632 = "didEndDisplayingHeaderView" fullword
    $s1633 = "leftRightGridient" fullword
    $s1634 = "setAlertViewStyle" fullword
    $s1638 = "NSLayoutConstraint" fullword
    $s1639 = "shouldSaveApplicationState" fullword
    $s1646 = "AECreateAppleEvent" fullword
    $s1653 = "getRequiredClass" fullword
    $s1654 = "ARCLiteIndexedSubscripting" fullword
    $s1668 = "kSecMatchLimitAll" fullword
    $s1670 = "initializeClassPair" fullword
    $s1676 = "EXUa2Kc9Qd9ysfHNqqIFg" fullword
    $s1700 = "applicationShouldOpenUntitledFile" fullword
    $s1704 = "stringWithCapacity" fullword
    $s1711 = "applicationShouldHandleReopen" fullword
    $s1712 = "objectAtIndexedSubscriptP7NSArrayP13objc" fullword
    $s1714 = "SecTransformExecute" fullword
    $s1718 = "gzippedDataWithCompressionLevel" fullword
    $s1726 = "initWithIdentifier" fullword
    $s1737 = "cancelAllOperations" fullword
    $s1738 = "dataTaskWithRequest" fullword
    $s1745 = "127clEvE15obfuscated" fullword
    $s1748 = "kZBUNetworkReachabilityDidChangeNotification" fullword
    $s1758 = "fkzienviptjqzaavumcectmwezot" fullword
    $s1759 = "ZL16scanMangledFieldRPKcS0" fullword
    $s1761 = "CFBundleExecutable" fullword
    $s1770 = "getTupleTypeMetadata2" fullword
    $s1790 = "ZL22copySwiftV1MangledNamePKcb" fullword
    $s1800 = "setAllowedFileTypes" fullword
    $s1803 = "fileManagerByPreservingAuthorizationRights" fullword
    $s1819 = "didRegisterForRemoteNotificationsWithDeviceToken" fullword
    $s1828 = "TZFE10FoundationSS36" fullword
    $s1831 = "willResizeForVersionBrowserWithMaxPreferredSize" fullword
    $s1858 = "applicationDidResignActive" fullword
    $s1869 = "componentsSeparatedByCharactersInSet" fullword
    $s1874 = "didDismissWithButtonIndex" fullword
    $s1880 = "ARARARARARARARARARARARARARARARARARARARBRB" fullword
    $s1890 = "scanJSONKeyValueSeparator" fullword
    $s1891 = "SUFileOpRemoveCommand" fullword
    $s1920 = "invocationWithTarget" fullword
    $s1924 = "setHTTPShouldHandleCookies" fullword

  condition:
    ((#s0 <= 0.5)
      and ((#s1 <= 1.5)
        and ((#s2 <= 1.5)
          and ((#s3 <= 0.5)
            and ((#s4 <= 2.5)
              and ((#s5 <= 0.5)
                and ((#s6 <= 1.5)
                  and ((#s7 <= 0.5)
                    and ((#s8 <= 0.5)
                      and ((#s9 <= 0.5)
                        and ((#s10 <= 0.5)
                          and ((#s11 <= 0.5)
                            and ((#s12 <= 0.5)
                              and ((#s13 <= 0.5)
                                and ((#s14 <= 1.0)
                                  and ((#s15 <= 0.5)
                                    and ((#s16 <= 0.5)
                                      and ((#s17 <= 0.5)
                                        and ((#s18 <= 17.5)
                                          and ((#s19 <= 0.5)
                                            and ((#s20 <= 1.5)
                                              and ((#s21 <= 0.5)
                                                and ((filesize <= 50188.0)
                                                  and ((#s23 <= 0.5)
                                                    and ((#s24 <= 0.5)
                                                      and ((#s25 <= 0.5)
                                                        and ((#s26 <= 1.5)
                                                          and ((#s27 <= 0.5)
                                                            and ((#s28 <= 0.5)
                                                              and ((#s29 <= 0.5)
                                                                and ((#s30 <= 2.0)
                                                                  and ((#s31 <= 0.5)
                                                                    and ((#s32 <= 0.5)
                                                                      and ((#s33 <= 0.5)
                                                                        and ((#s34 <= 0.5)
                                                                          and ((#s35 <= 1.5)
                                                                            and ((#s36 <= 0.5)
                                                                              and ((#s37 <= 0.5)
                                                                                and ((#s26 <= 0.5)
                                                                                  and ((#s39 <= 0.5)
                                                                                    and ((#s40 <= 0.5)
                                                                                      and ((#s41 <= 0.5)
                                                                                        and ((#s42 <= 0.5)
                                                                                          and ((#s43 <= 0.5)
                                                                                            and ((#s44 <= 0.5)
                                                                                              and ((#s45 <= 0.5)
                                                                                                and ((#s46 <= 0.5)
                                                                                                  and ((#s47 <= 0.5)
                                                                                                    and ((#s48 <= 0.5)
                                                                                                      and ((#s49 <= 0.5)
                                                                                                        and ((#s50 <= 0.5)
                                                                                                          and ((#s51 <= 1.0)
                                                                                                            and ((#s52 <= 0.5)
                                                                                                              and ((#s53 <= 0.5)
                                                                                                                and ((filesize <= 50006.0)
                                                                                                                  and ((#s55 <= 0.5)
                                                                                                                    and ((#s56 <= 1.5)
                                                                                                                      and ((#s57 <= 0.5)
                                                                                                                        and ((#s58 <= 0.5)
                                                                                                                          and ((#s59 <= 0.5)
                                                                                                                            and ((#s60 <= 0.5)
                                                                                                                              and ((#s61 <= 0.5)
                                                                                                                                and ((#s62 <= 0.5)
                                                                                                                                  and ((#s63 <= 0.5)
                                                                                                                                    and ((#s64 <= 1.5)
                                                                                                                                      and ((#s65 <= 0.5)
                                                                                                                                        and ((#s66 <= 0.5)
                                                                                                                                          and ((#s67 <= 0.5)
                                                                                                                                            and ((#s68 <= 0.5)
                                                                                                                                              and ((#s69 <= 0.5)
                                                                                                                                                and ((#s70 <= 0.5)
                                                                                                                                                  and ((#s71 <= 3.0)
                                                                                                                                                    and ((#s72 <= 0.5)
                                                                                                                                                      and ((#s73 <= 0.5)
                                                                                                                                                        and ((#s74 <= 0.5)
                                                                                                                                                          and ((#s75 <= 0.5)
                                                                                                                                                            and ((#s76 <= 0.5)
                                                                                                                                                              and ((#s77 <= 0.5)
                                                                                                                                                                and ((#s78 <= 0.5)
                                                                                                                                                                  and ((filesize <= 16444.0)
                                                                                                                                                                    and ((#s80 <= 0.5)
                                                                                                                                                                      and ((#s81 <= 1.0)
                                                                                                                                                                        and ((#s82 <= 0.5)
                                                                                                                                                                          and ((#s83 <= 0.5)
                                                                                                                                                                            and ((#s84 <= 0.5)
                                                                                                                                                                              and ((#s85 <= 0.5)
                                                                                                                                                                                and ((#s86 <= 1.0)
                                                                                                                                                                                  and ((#s87 <= 0.5)
                                                                                                                                                                                    and ((#s88 <= 0.5)
                                                                                                                                                                                      and ((#s89 <= 0.5)
                                                                                                                                                                                        and ((#s90 <= 0.5)
                                                                                                                                                                                          and ((#s91 <= 0.5)
                                                                                                                                                                                            and ((filesize > 4198.0)
                                                                                                                                                                                              and ((#s94 <= 0.5)
                                                                                                                                                                                                and ((#s95 <= 1.0)
                                                                                                                                                                                                  and ((#s96 <= 0.5)
                                                                                                                                                                                                    and ((#s97 <= 0.5)
                                                                                                                                                                                                      and ((#s98 <= 3.0)
                                                                                                                                                                                                        and ((#s99 <= 0.5)
                                                                                                                                                                                                          and ((#s100 <= 0.5)
                                                                                                                                                                                                            and ((#s101 <= 0.5)
                                                                                                                                                                                                              and ((filesize > 4226.0)
                                                                                                                                                                                                                and ((#s104 <= 1.0)
                                                                                                                                                                                                                  and ((filesize <= 5206.5)
                                                                                                                                                                                                                    and ((filesize > 5176.0)
                                                                                                                                                                                                                    ))))))))))))))))))))))))) or (filesize > 16444.0)
                                                                                                                                                                    and ((#s87 <= 0.5)
                                                                                                                                                                      and ((filesize <= 16478.0)
                                                                                                                                                                        or (filesize > 16478.0)
                                                                                                                                                                        and ((#s134 <= 0.5)
                                                                                                                                                                          and ((#s135 <= 0.5)
                                                                                                                                                                            and ((#s104 <= 1.0)
                                                                                                                                                                              and ((#s35 <= 0.5)
                                                                                                                                                                                and ((#s138 <= 1.0)
                                                                                                                                                                                  and ((#s80 <= 0.5)
                                                                                                                                                                                    and ((#s98 <= 1.0)
                                                                                                                                                                                      and ((#s96 <= 0.5)
                                                                                                                                                                                        and ((#s142 <= 0.5)
                                                                                                                                                                                          and ((#s95 <= 4.0)
                                                                                                                                                                                            and ((#s144 <= 0.5)
                                                                                                                                                                                              and ((#s145 <= 1.0)
                                                                                                                                                                                                and ((#s82 <= 0.5)
                                                                                                                                                                                                  and ((#s147 <= 1.0)
                                                                                                                                                                                                    and ((#s148 <= 0.5)
                                                                                                                                                                                                      and ((#s149 <= 0.5)
                                                                                                                                                                                                        and ((#s150 <= 0.5)
                                                                                                                                                                                                          and ((#s151 <= 0.5)
                                                                                                                                                                                                            and ((#s152 <= 0.5)
                                                                                                                                                                                                              and ((#s153 <= 0.5)
                                                                                                                                                                                                                and ((#s154 <= 0.5)
                                                                                                                                                                                                                  and ((#s155 <= 0.5)
                                                                                                                                                                                                                    and ((#s156 <= 0.5)
                                                                                                                                                                                                                      and ((#s157 <= 1.0)
                                                                                                                                                                                                                        and ((#s158 <= 0.5)
                                                                                                                                                                                                                          and ((#s159 <= 0.5)
                                                                                                                                                                                                                            and ((#s94 <= 0.5)
                                                                                                                                                                                                                              and ((#s85 <= 1.5)
                                                                                                                                                                                                                                and ((#s162 <= 0.5)
                                                                                                                                                                                                                                  and ((filesize <= 21672.0)
                                                                                                                                                                                                                                    and ((#s89 <= 0.5)
                                                                                                                                                                                                                                      and ((#s91 <= 0.5)
                                                                                                                                                                                                                                        and ((#s85 <= 0.5)
                                                                                                                                                                                                                                          and ((filesize <= 20712.0)
                                                                                                                                                                                                                                            and ((#s168 <= 1.0)
                                                                                                                                                                                                                                              and ((#s88 <= 0.5)
                                                                                                                                                                                                                                                and ((filesize > 18966.0)
                                                                                                                                                                                                                                                  and ((filesize <= 19022.0)
                                                                                                                                                                                                                                                  )))) or (filesize > 20712.0)
                                                                                                                                                                                                                                            and ((filesize <= 20832.0)
                                                                                                                                                                                                                                              or (filesize > 20832.0)
                                                                                                                                                                                                                                              and ((filesize <= 21624.0)
                                                                                                                                                                                                                                                and ((filesize <= 21056.0)
                                                                                                                                                                                                                                                  and ((filesize > 21044.0)
                                                                                                                                                                                                                                                  )) or (filesize > 21624.0)
                                                                                                                                                                                                                                              )))))) or (filesize > 21672.0)
                                                                                                                                                                                                                                    and ((#s91 <= 0.5)
                                                                                                                                                                                                                                      and ((#s190 <= 0.5)
                                                                                                                                                                                                                                        and ((#s191 <= 1.0)
                                                                                                                                                                                                                                          and ((#s88 <= 0.5)
                                                                                                                                                                                                                                            and ((filesize <= 26130.0)
                                                                                                                                                                                                                                              and ((#s85 <= 0.5)
                                                                                                                                                                                                                                                and ((filesize <= 26044.0)
                                                                                                                                                                                                                                                  and ((filesize > 25072.0)
                                                                                                                                                                                                                                                    and ((filesize <= 25220.0)
                                                                                                                                                                                                                                                    )) or (filesize > 26044.0)
                                                                                                                                                                                                                                                ))))))))) or (#s85 > 1.5)
                                                                                                                                                                                                                                and ((filesize > 39022.0)
                                                                                                                                                                                                                                  and ((#s91 > 0.5)
                                                                                                                                                                                                                                  ))))))))) or (#s154 > 0.5)
                                                                                                                                                                                                                  and ((filesize <= 37672.0)
                                                                                                                                                                                                                  )) or (#s153 > 0.5)
                                                                                                                                                                                                              ))))))))))))))))))))))) or (#s78 > 0.5)
                                                                                                                                                                ))))))) or (#s71 > 3.0)
                                                                                                                                                  )) or (#s69 > 0.5)
                                                                                                                                                and ((#s168 <= 1.0)
                                                                                                                                                  and ((#s254 <= 0.5)
                                                                                                                                                    and ((#s69 <= 1.5)
                                                                                                                                                      and ((#s75 <= 1.0)
                                                                                                                                                        and ((#s257 <= 0.5)
                                                                                                                                                          and ((#s82 <= 1.0)
                                                                                                                                                            and ((#s147 <= 1.0)
                                                                                                                                                              and ((#s260 <= 2.0)
                                                                                                                                                                and ((#s261 <= 0.5)
                                                                                                                                                                  and ((#s262 <= 1.0)
                                                                                                                                                                    and ((#s98 <= 1.0)
                                                                                                                                                                      and ((#s264 <= 0.5)
                                                                                                                                                                        and ((#s265 <= 0.5)
                                                                                                                                                                          and ((#s154 <= 0.5)
                                                                                                                                                                            and ((#s81 <= 1.0)
                                                                                                                                                                              and ((#s76 <= 1.0)
                                                                                                                                                                                and ((#s269 <= 0.5)
                                                                                                                                                                                  and ((filesize <= 36656.0)
                                                                                                                                                                                    and ((#s77 <= 1.0)
                                                                                                                                                                                      and ((#s135 <= 1.0)
                                                                                                                                                                                        and ((#s87 > 1.5)
                                                                                                                                                                                          and ((#s275 > 0.5)
                                                                                                                                                                                          )))) or (filesize > 36656.0)
                                                                                                                                                                                    and ((filesize <= 36800.0)
                                                                                                                                                                                    ))))) or (#s154 > 0.5)
                                                                                                                                                                            and ((filesize <= 38920.0)
                                                                                                                                                                            ))))) or (#s262 > 1.0)
                                                                                                                                                                  ))))))))))) or (#s68 > 0.5)
                                                                                                                                              and ((#s73 <= 0.5)
                                                                                                                                                and ((#s82 > 1.0)
                                                                                                                                                )))))) or (#s64 > 1.5)
                                                                                                                                      and ((#s87 > 1.0)
                                                                                                                                        and ((#s76 > 1.0)
                                                                                                                                        )))) or (#s62 > 0.5)
                                                                                                                                ) or (#s61 > 0.5)
                                                                                                                              ) or (#s60 > 0.5)
                                                                                                                            ) or (#s59 > 0.5)
                                                                                                                          ) or (#s58 > 0.5)
                                                                                                                        )) or (#s56 > 1.5)
                                                                                                                      and ((#s73 > 0.5)
                                                                                                                      )) or (#s55 > 0.5)
                                                                                                                    and ((#s257 <= 0.5)
                                                                                                                      and ((#s134 <= 1.0)
                                                                                                                        and ((#s67 <= 1.0)
                                                                                                                          and ((#s69 > 0.5)
                                                                                                                            and ((#s82 <= 1.0)
                                                                                                                              and ((#s269 <= 0.5)
                                                                                                                                and ((filesize <= 27528.0)
                                                                                                                                )))))))) or (filesize > 50006.0)
                                                                                                                  and ((#s104 <= 1.5)
                                                                                                                    and ((filesize <= 50174.5)
                                                                                                                      or (filesize > 50174.5)
                                                                                                                      and ((filesize > 50178.5)
                                                                                                                      )))) or (#s53 > 0.5)
                                                                                                                and ((#s87 <= 1.0)
                                                                                                                  and ((#s85 <= 1.0)
                                                                                                                    and ((filesize <= 25456.0)
                                                                                                                    )))) or (#s52 > 0.5)
                                                                                                            ) or (#s51 > 1.0)
                                                                                                          )) or (#s49 > 0.5)
                                                                                                      ) or (#s48 > 0.5)
                                                                                                    ) or (#s47 > 0.5)
                                                                                                  ) or (#s46 > 0.5)
                                                                                                ) or (#s45 > 0.5)
                                                                                                and ((#s87 > 1.0)
                                                                                                )) or (#s44 > 0.5)
                                                                                              and ((filesize <= 35234.0)
                                                                                              ))))) or (#s40 > 0.5)
                                                                                    ))) or (#s37 > 0.5)
                                                                                and ((filesize > 23106.0)
                                                                                  and ((#s86 <= 1.0)
                                                                                  ))) or (#s36 > 0.5)
                                                                            ) or (#s35 > 1.5)
                                                                          )) or (#s33 > 0.5)
                                                                      ) or (#s32 > 0.5)
                                                                      and ((#s265 <= 0.5)
                                                                        and ((#s101 <= 1.0)
                                                                          and ((#s97 <= 0.5)
                                                                            and ((#s83 <= 0.5)
                                                                              and ((#s386 <= 1.0)
                                                                                and ((#s86 <= 0.5)
                                                                                  and ((#s100 <= 0.5)
                                                                                    and ((#s389 <= 0.5)
                                                                                      and ((#s66 <= 0.5)
                                                                                        and ((#s39 <= 0.5)
                                                                                          and ((#s99 <= 0.5)
                                                                                            and ((filesize > 19128.0)
                                                                                              and ((#s98 <= 1.0)
                                                                                                and ((filesize <= 21276.0)
                                                                                                ))))))))) or (#s386 > 1.0)
                                                                                and ((#s389 <= 0.5)
                                                                                  and ((#s100 <= 0.5)
                                                                                    and ((#s86 <= 1.0)
                                                                                      and ((#s66 > 0.5)
                                                                                      ) or (#s86 > 1.0)
                                                                                      and ((filesize > 8318.0)
                                                                                        and ((filesize <= 26556.0)
                                                                                        )))))))))))) or (#s30 > 2.0)
                                                                ) or (#s29 > 0.5)
                                                                and ((#s66 <= 1.5)
                                                                  and ((#s426 <= 2.5)
                                                                    and ((filesize <= 19912.0)
                                                                    ) or (#s426 > 2.5)
                                                                  ) or (#s66 > 1.5)
                                                                  and ((filesize <= 20408.0)
                                                                  ))) or (#s28 > 0.5)
                                                            ) or (#s27 > 0.5)
                                                          ) or (#s26 > 1.5)
                                                          and ((#s436 > 0.5)
                                                            and ((#s438 <= 1.0)
                                                            ))) or (#s25 > 0.5)
                                                      ) or (#s24 > 0.5)
                                                      and ((#s442 > 1.0)
                                                      ))) or (filesize > 50188.0)
                                                  and ((#s446 <= 0.5)
                                                    and ((#s257 <= 0.5)
                                                      and ((#s448 <= 1.0)
                                                        and ((#s449 <= 0.5)
                                                          and ((#s450 <= 1.5)
                                                            and ((#s190 <= 0.5)
                                                              and ((#s452 <= 0.5)
                                                                and ((#s453 <= 1.0)
                                                                  and ((#s82 <= 0.5)
                                                                    and ((#s455 <= 1.0)
                                                                      and ((#s456 <= 1.5)
                                                                        and ((#s23 <= 0.5)
                                                                          and ((#s458 <= 0.5)
                                                                            and ((#s459 <= 1.0)
                                                                              and ((#s460 <= 0.5)
                                                                                and ((#s461 <= 0.5)
                                                                                  and ((#s462 <= 0.5)
                                                                                    and ((#s463 <= 1.0)
                                                                                      and ((#s464 <= 0.5)
                                                                                        and ((#s465 <= 0.5)
                                                                                          and ((#s386 <= 1.5)
                                                                                            and ((#s63 <= 5.5)
                                                                                              and ((#s468 <= 0.5)
                                                                                                and ((#s97 <= 0.5)
                                                                                                  and ((#s470 <= 1.0)
                                                                                                    and ((#s62 <= 0.5)
                                                                                                      and ((#s68 <= 1.5)
                                                                                                        and ((#s473 <= 0.5)
                                                                                                          and ((#s83 <= 0.5)
                                                                                                            and ((#s254 <= 0.5)
                                                                                                              and ((#s77 <= 0.5)
                                                                                                                and ((#s477 <= 0.5)
                                                                                                                  and ((#s158 <= 0.5)
                                                                                                                    and ((#s479 <= 1.0)
                                                                                                                      and ((#s480 <= 0.5)
                                                                                                                        and ((#s95 <= 2.5)
                                                                                                                          and ((#s426 <= 1.5)
                                                                                                                            and ((#s483 <= 0.5)
                                                                                                                              and ((#s484 <= 0.5)
                                                                                                                                and ((#s485 <= 0.5)
                                                                                                                                  and ((#s486 <= 0.5)
                                                                                                                                    and ((filesize <= 170316.0)
                                                                                                                                      and ((#s265 <= 0.5)
                                                                                                                                        and ((#s489 <= 1.0)
                                                                                                                                          and ((#s67 <= 1.0)
                                                                                                                                            and ((#s159 <= 0.5)
                                                                                                                                              and ((#s492 <= 0.5)
                                                                                                                                                and ((#s148 <= 0.5)
                                                                                                                                                  and ((#s494 <= 0.5)
                                                                                                                                                    and ((#s495 <= 0.5)
                                                                                                                                                      and ((#s43 <= 0.5)
                                                                                                                                                        and ((#s497 <= 0.5)
                                                                                                                                                          and ((#s69 <= 0.5)
                                                                                                                                                            and ((#s91 <= 0.5)
                                                                                                                                                              and ((#s142 <= 0.5)
                                                                                                                                                                and ((#s84 <= 0.5)
                                                                                                                                                                  and ((#s76 <= 0.5)
                                                                                                                                                                    and ((#s154 <= 0.5)
                                                                                                                                                                      and ((#s94 <= 0.5)
                                                                                                                                                                        and ((#s85 <= 0.5)
                                                                                                                                                                          and ((#s39 <= 0.5)
                                                                                                                                                                            and ((#s507 <= 0.5)
                                                                                                                                                                              and ((#s153 <= 0.5)
                                                                                                                                                                                and ((#s162 <= 0.5)
                                                                                                                                                                                  and ((#s24 <= 1.0)
                                                                                                                                                                                    and ((#s511 <= 0.5)
                                                                                                                                                                                      and ((#s512 <= 1.0)
                                                                                                                                                                                        and ((#s73 <= 0.5)
                                                                                                                                                                                          and ((#s87 <= 0.5)
                                                                                                                                                                                            and ((#s75 <= 1.0)
                                                                                                                                                                                              and ((#s144 <= 0.5)
                                                                                                                                                                                                and ((#s261 <= 0.5)
                                                                                                                                                                                                  and ((#s518 <= 1.0)
                                                                                                                                                                                                    and ((#s157 <= 1.0)
                                                                                                                                                                                                      and ((#s53 <= 2.0)
                                                                                                                                                                                                        and ((#s81 <= 1.0)
                                                                                                                                                                                                          and ((filesize <= 71394.0)
                                                                                                                                                                                                            and ((#s523 <= 1.0)
                                                                                                                                                                                                              and ((#s66 <= 1.0)
                                                                                                                                                                                                                and ((filesize > 71222.0)
                                                                                                                                                                                                                ))))))))))))))))))))))))))) or (#s69 > 0.5)
                                                                                                                                                            and ((filesize <= 69828.0)
                                                                                                                                                              and ((#s87 <= 3.0)
                                                                                                                                                                and ((#s75 <= 1.0)
                                                                                                                                                                  and ((#s55 > 0.5)
                                                                                                                                                                    and ((#s559 > 0.5)
                                                                                                                                                                    )))))))))))))))) or (filesize > 170316.0)
                                                                                                                                      and ((#s39 <= 0.5)
                                                                                                                                        and ((#s55 <= 0.5)
                                                                                                                                          and ((#s495 <= 1.5)
                                                                                                                                            and ((#s86 <= 1.0)
                                                                                                                                              and ((#s579 <= 0.5)
                                                                                                                                                and ((#s64 <= 0.5)
                                                                                                                                                  and ((#s156 <= 0.5)
                                                                                                                                                    and ((#s582 <= 0.5)
                                                                                                                                                      and ((#s265 <= 0.5)
                                                                                                                                                        and ((#s87 <= 0.5)
                                                                                                                                                          and ((#s53 <= 0.5)
                                                                                                                                                            and ((#s586 <= 0.5)
                                                                                                                                                              and ((#s162 <= 0.5)
                                                                                                                                                                and ((#s588 <= 0.5)
                                                                                                                                                                  and ((#s589 <= 0.5)
                                                                                                                                                                    and ((#s590 <= 0.5)
                                                                                                                                                                      and ((filesize <= 173732.0)
                                                                                                                                                                        and ((#s85 <= 0.5)
                                                                                                                                                                          and ((#s75 <= 1.0)
                                                                                                                                                                            and ((filesize <= 173138.0)
                                                                                                                                                                              and ((filesize <= 170796.0)
                                                                                                                                                                              ) or (filesize > 173138.0)
                                                                                                                                                                            ))) or (filesize > 173732.0)
                                                                                                                                                                        and ((#s145 <= 91.0)
                                                                                                                                                                          and ((#s43 <= 0.5)
                                                                                                                                                                            and ((#s603 <= 1.0)
                                                                                                                                                                              and ((#s604 <= 0.5)
                                                                                                                                                                                and ((#s104 <= 1.0)
                                                                                                                                                                                  and ((#s606 <= 0.5)
                                                                                                                                                                                    and ((#s607 <= 1.0)
                                                                                                                                                                                      and ((#s157 <= 0.5)
                                                                                                                                                                                        and ((#s609 <= 0.5)
                                                                                                                                                                                          and ((#s426 <= 0.5)
                                                                                                                                                                                            and ((#s56 <= 0.5)
                                                                                                                                                                                              and ((#s85 <= 0.5)
                                                                                                                                                                                                and ((#s96 <= 0.5)
                                                                                                                                                                                                  and ((#s495 <= 0.5)
                                                                                                                                                                                                    and ((#s24 <= 0.5)
                                                                                                                                                                                                      and ((#s95 <= 0.5)
                                                                                                                                                                                                        and ((#s617 <= 1.0)
                                                                                                                                                                                                          and ((#s144 <= 0.5)
                                                                                                                                                                                                            and ((#s619 <= 0.5)
                                                                                                                                                                                                              and ((#s620 <= 0.5)
                                                                                                                                                                                                                and ((#s32 <= 1.0)
                                                                                                                                                                                                                  and ((#s262 <= 0.5)
                                                                                                                                                                                                                    and ((#s94 <= 0.5)
                                                                                                                                                                                                                      and ((#s67 <= 0.5)
                                                                                                                                                                                                                        and ((#s134 <= 0.5)
                                                                                                                                                                                                                          and ((#s626 <= 1.0)
                                                                                                                                                                                                                            and ((#s147 <= 1.0)
                                                                                                                                                                                                                              and ((#s31 <= 12.5)
                                                                                                                                                                                                                                and ((#s66 <= 1.0)
                                                                                                                                                                                                                                  and ((#s35 <= 0.5)
                                                                                                                                                                                                                                    and ((#s154 <= 0.5)
                                                                                                                                                                                                                                      and ((#s135 <= 1.0)
                                                                                                                                                                                                                                        and ((#s90 <= 1.5)
                                                                                                                                                                                                                                          and ((#s634 <= 0.5)
                                                                                                                                                                                                                                            and ((#s91 <= 0.5)
                                                                                                                                                                                                                                              and ((#s68 <= 0.5)
                                                                                                                                                                                                                                                and ((#s637 <= 0.5)
                                                                                                                                                                                                                                                  and ((#s638 <= 0.5)
                                                                                                                                                                                                                                                    and ((filesize > 411508.0)
                                                                                                                                                                                                                                                      and ((#s75 <= 1.0)
                                                                                                                                                                                                                                                        and ((filesize <= 464060.0)
                                                                                                                                                                                                                                                          and ((filesize <= 457316.0)
                                                                                                                                                                                                                                                            and ((filesize <= 415252.0)
                                                                                                                                                                                                                                                            ) or (filesize > 457316.0)
                                                                                                                                                                                                                                                          ) or (filesize > 464060.0)
                                                                                                                                                                                                                                                          and ((filesize <= 628914.0)
                                                                                                                                                                                                                                                            and ((filesize > 615352.0)
                                                                                                                                                                                                                                                            ) or (filesize > 628914.0)
                                                                                                                                                                                                                                                            and ((filesize > 1677491.5)
                                                                                                                                                                                                                                                              and ((filesize <= 1724018.5)
                                                                                                                                                                                                                                                              ))))))))))))))))))))))) or (#s32 > 1.0)
                                                                                                                                                                                                                  and ((#s70 <= 0.5)
                                                                                                                                                                                                                    and ((#s75 <= 1.0)
                                                                                                                                                                                                                      and ((filesize > 586436.0)
                                                                                                                                                                                                                        and ((#s68 <= 0.5)
                                                                                                                                                                                                                          and ((filesize <= 624612.0)
                                                                                                                                                                                                                          )))))))))))) or (#s495 > 0.5)
                                                                                                                                                                                                    and ((#s75 <= 1.0)
                                                                                                                                                                                                      and ((#s494 <= 0.5)
                                                                                                                                                                                                        and ((filesize > 3230809.0)
                                                                                                                                                                                                          and ((filesize <= 14425004.0)
                                                                                                                                                                                                          ))) or (#s75 > 1.0)
                                                                                                                                                                                                      and ((#s144 <= 14.5)
                                                                                                                                                                                                        and ((#s32 <= 1.0)
                                                                                                                                                                                                        ))))) or (#s85 > 0.5)
                                                                                                                                                                                                and ((#s619 <= 0.5)
                                                                                                                                                                                                  and ((#s507 <= 0.5)
                                                                                                                                                                                                    and ((#s495 <= 0.5)
                                                                                                                                                                                                      and ((#s91 <= 0.5)
                                                                                                                                                                                                        and ((#s147 <= 0.5)
                                                                                                                                                                                                          and ((#s67 <= 1.0)
                                                                                                                                                                                                            and ((#s154 <= 0.5)
                                                                                                                                                                                                              and ((#s94 <= 0.5)
                                                                                                                                                                                                                and ((#s714 <= 0.5)
                                                                                                                                                                                                                  and ((filesize <= 294886.0)
                                                                                                                                                                                                                    and ((#s68 <= 0.5)
                                                                                                                                                                                                                      and ((filesize > 289870.0)
                                                                                                                                                                                                                      ))))))))))))))))))))))))))) or (#s588 > 0.5)
                                                                                                                                                                ))) or (#s53 > 0.5)
                                                                                                                                                            and ((#s162 <= 1.0)
                                                                                                                                                              and ((filesize > 622711.5)
                                                                                                                                                              ))) or (#s87 > 0.5)
                                                                                                                                                          and ((#s32 <= 1.0)
                                                                                                                                                            and ((#s753 <= 0.5)
                                                                                                                                                              and ((#s607 <= 0.5)
                                                                                                                                                                and ((#s135 <= 1.0)
                                                                                                                                                                  and ((#s494 <= 0.5)
                                                                                                                                                                    and ((#s67 <= 0.5)
                                                                                                                                                                      and ((#s154 <= 0.5)
                                                                                                                                                                        and ((#s492 <= 1.0)
                                                                                                                                                                          and ((#s69 <= 1.5)
                                                                                                                                                                            and ((#s94 <= 0.5)
                                                                                                                                                                              and ((#s762 <= 1.0)
                                                                                                                                                                                and ((#s495 > 0.5)
                                                                                                                                                                                  and ((filesize <= 321685.5)
                                                                                                                                                                                  )))))) or (#s154 > 0.5)
                                                                                                                                                                        and ((#s87 > 1.5)
                                                                                                                                                                          and ((#s144 <= 0.5)
                                                                                                                                                                            and ((#s154 <= 1.5)
                                                                                                                                                                              and ((#s85 <= 1.0)
                                                                                                                                                                                and ((#s94 > 0.5)
                                                                                                                                                                                ))))))))))))))))))))))))))) or (#s426 > 1.5)
                                                                                                                            and ((#s87 <= 1.0)
                                                                                                                              and ((#s135 > 2.0)
                                                                                                                              ))) or (#s95 > 2.5)
                                                                                                                          and ((#s807 <= 1.0)
                                                                                                                            and ((#s808 <= 1.0)
                                                                                                                              and ((#s157 > 1.5)
                                                                                                                                and ((#s589 <= 1.0)
                                                                                                                                  and ((#s812 > 0.5)
                                                                                                                                  ))))))) or (#s479 > 1.0)
                                                                                                                    ))) or (#s77 > 0.5)
                                                                                                                and ((#s134 <= 0.5)
                                                                                                                  and ((#s823 <= 0.5)
                                                                                                                    and ((#s73 <= 0.5)
                                                                                                                      and ((#s825 <= 2.0)
                                                                                                                        and ((#s426 <= 0.5)
                                                                                                                          and ((#s157 <= 1.0)
                                                                                                                            and ((#s57 <= 0.5)
                                                                                                                              and ((#s32 <= 0.5)
                                                                                                                                and ((#s66 > 0.5)
                                                                                                                                  and ((#s142 > 0.5)
                                                                                                                                  )))))))) or (#s823 > 0.5)
                                                                                                                    and ((#s32 > 0.5)
                                                                                                                    )) or (#s134 > 0.5)
                                                                                                                  and ((#s823 <= 0.5)
                                                                                                                    and ((#s77 <= 1.5)
                                                                                                                      and ((#s846 <= 0.5)
                                                                                                                        and ((#s87 <= 0.5)
                                                                                                                          and ((#s848 <= 0.5)
                                                                                                                            and ((#s66 <= 1.0)
                                                                                                                              and ((#s134 <= 2.0)
                                                                                                                                and ((#s851 <= 0.5)
                                                                                                                                  and ((filesize > 1575542.5)
                                                                                                                                  )))))))))))) or (#s83 > 0.5)
                                                                                                            and ((#s69 <= 0.5)
                                                                                                              and ((#s865 <= 0.5)
                                                                                                                and ((#s609 > 0.5)
                                                                                                                  and ((#s868 <= 0.5)
                                                                                                                    and ((#s851 <= 0.5)
                                                                                                                      and ((#s870 <= 0.5)
                                                                                                                        and ((#s871 > 1.0)
                                                                                                                        )))))))) or (#s473 > 0.5)
                                                                                                          and ((#s63 > 0.5)
                                                                                                          )) or (#s68 > 1.5)
                                                                                                        and ((#s96 <= 0.5)
                                                                                                          and ((#s883 <= 0.5)
                                                                                                            and ((#s589 <= 0.5)
                                                                                                              and ((#s55 <= 0.5)
                                                                                                                and ((#s265 <= 0.5)
                                                                                                                  and ((#s69 <= 0.5)
                                                                                                                    and ((#s888 <= 6.0)
                                                                                                                      and ((#s147 <= 0.5)
                                                                                                                        and ((#s156 <= 0.5)
                                                                                                                          and ((#s891 <= 0.5)
                                                                                                                            and ((#s70 <= 1.0)
                                                                                                                              and ((#s154 <= 0.5)
                                                                                                                                and ((#s94 <= 0.5)
                                                                                                                                  and ((filesize <= 501929.5)
                                                                                                                                    and ((#s87 <= 0.5)
                                                                                                                                      and ((#s68 <= 3.0)
                                                                                                                                        and ((filesize > 444223.5)
                                                                                                                                        )))))))))))))))))) or (#s62 > 0.5)
                                                                                                    ) or (#s470 > 1.0)
                                                                                                    and ((#s918 > 2.5)
                                                                                                    ))) or (#s468 > 0.5)
                                                                                              ) or (#s63 > 5.5)
                                                                                            ) or (#s386 > 1.5)
                                                                                            and ((#s142 <= 0.5)
                                                                                              and ((#s925 <= 0.5)
                                                                                                and ((#s39 <= 0.5)
                                                                                                  and ((#s927 <= 0.5)
                                                                                                    and ((#s77 <= 0.5)
                                                                                                      and ((#s87 <= 1.0)
                                                                                                        and ((#s66 <= 0.5)
                                                                                                          and ((#s931 <= 0.5)
                                                                                                            and ((#s932 <= 0.5)
                                                                                                              and ((#s86 > 1.0)
                                                                                                                and ((filesize <= 976710.0)
                                                                                                                )) or (#s932 > 0.5)
                                                                                                              and ((filesize <= 7578068.0)
                                                                                                              ))) or (#s66 > 0.5)
                                                                                                        ))))))))) or (#s464 > 0.5)
                                                                                      ) or (#s463 > 1.0)
                                                                                    )) or (#s461 > 0.5)
                                                                                ) or (#s460 > 0.5)
                                                                                and ((#s75 <= 1.0)
                                                                                  and ((#s162 > 0.5)
                                                                                    and ((#s95 <= 237.5)
                                                                                      and ((#s95 > 91.5)
                                                                                      ))) or (#s75 > 1.0)
                                                                                  and ((#s619 > 2.0)
                                                                                  ))) or (#s459 > 1.0)
                                                                            ) or (#s458 > 0.5)
                                                                          ) or (#s23 > 0.5)
                                                                          and ((#s969 <= 2.5)
                                                                            and ((#s147 <= 0.5)
                                                                              and ((#s971 <= 0.5)
                                                                                and ((#s42 <= 0.5)
                                                                                  and ((#s918 <= 0.5)
                                                                                    and ((#s57 <= 0.5)
                                                                                      and ((#s975 <= 0.5)
                                                                                        and ((#s39 <= 0.5)
                                                                                          and ((#s518 <= 1.0)
                                                                                            and ((#s69 <= 0.5)
                                                                                              and ((#s134 > 0.5)
                                                                                              )))))))))) or (#s969 > 2.5)
                                                                          )) or (#s456 > 1.5)
                                                                      ) or (#s455 > 1.0)
                                                                    ) or (#s82 > 0.5)
                                                                    and ((#s56 <= 0.5)
                                                                      and ((#s75 > 1.0)
                                                                        and ((#s55 <= 0.5)
                                                                          and ((#s497 <= 0.5)
                                                                            and ((#s999 > 1.0)
                                                                              and ((#s162 <= 0.5)
                                                                                and ((#s823 <= 1.0)
                                                                                  and ((filesize > 2106278.0)
                                                                                  ))))))))) or (#s453 > 1.0)
                                                                ) or (#s452 > 0.5)
                                                              )) or (#s450 > 1.5)
                                                          ) or (#s449 > 0.5)
                                                        ) or (#s448 > 1.0)
                                                      ) or (#s257 > 0.5)
                                                      and ((#s77 <= 1.0)
                                                        and ((#s1018 <= 1.0)
                                                          and ((#s870 <= 1.0)
                                                            and ((#s1020 <= 1.0)
                                                              and ((#s617 <= 1.0)
                                                                and ((#s55 > 0.5)
                                                                ))))))) or (#s446 > 0.5)
                                                    and ((#s154 > 0.5)
                                                    ))) or (#s21 > 0.5)
                                                and ((#s75 <= 0.5)
                                                  and ((#s254 > 0.5)
                                                    and ((#s1036 <= 0.5)
                                                      and ((#s162 <= 0.5)
                                                        and ((#s1038 > 1.0)
                                                        )))) or (#s75 > 0.5)
                                                  and ((#s1043 <= 0.5)
                                                    and ((#s85 <= 1.0)
                                                      and ((#s81 <= 1.0)
                                                        and ((#s265 <= 0.5)
                                                          and ((#s254 <= 0.5)
                                                            and ((#s846 <= 1.0)
                                                              and ((#s80 <= 1.5)
                                                                and ((#s1050 <= 1.0)
                                                                  and ((#s150 <= 0.5)
                                                                    and ((#s1052 > 0.5)
                                                                    ) or (#s150 > 0.5)
                                                                  )))))))) or (#s1043 > 0.5)
                                                    and ((#s927 > 10.5)
                                                    )))) or (#s20 > 1.5)
                                              and ((#s168 <= 0.5)
                                                and ((#s158 <= 0.5)
                                                  and ((filesize <= 90256.0)
                                                    and ((#s32 > 1.0)
                                                      and ((#s386 > 1.0)
                                                        and ((#s1073 <= 0.5)
                                                          and ((filesize > 10528.0)
                                                            and ((filesize <= 18120.0)
                                                              and ((filesize <= 12038.0)
                                                                or (filesize > 12038.0)
                                                                and ((filesize > 14024.0)
                                                                  and ((filesize <= 16072.0)
                                                                  ))) or (filesize > 18120.0)
                                                            )) or (#s1073 > 0.5)
                                                        ))))))) or (#s19 > 0.5)
                                          ) or (#s18 > 17.5)
                                          and ((#s925 <= 0.5)
                                          )) or (#s17 > 0.5)
                                      ) or (#s16 > 0.5)
                                    ) or (#s15 > 0.5)
                                  ) or (#s14 > 1.0)
                                ) or (#s13 > 0.5)
                              ) or (#s12 > 0.5)
                            ) or (#s11 > 0.5)
                            and ((#s1099 <= 2.0)
                              and ((#s1100 <= 0.5)
                                and ((#s88 <= 3.0)
                                  and ((#s63 <= 0.5)
                                    and ((#s1103 <= 0.5)
                                      and ((#s1104 <= 0.5)
                                        and ((#s473 <= 0.5)
                                          and ((#s88 > 1.5)
                                            and ((#s150 <= 0.5)
                                              and ((#s26 <= 1.0)
                                                and ((#s1110 <= 1.0)
                                                  and ((#s149 <= 0.5)
                                                    and ((#s1112 <= 0.5)
                                                    ))) or (#s26 > 1.0)
                                              ))))) or (#s1103 > 0.5)
                                      and ((#s1121 <= 1.0)
                                        and ((filesize <= 10092017.0)
                                        ))) or (#s63 > 0.5)
                                  ))) or (#s1099 > 2.0)
                            )) or (#s10 > 0.5)
                          and ((#s32 <= 1.0)
                            and ((#s1131 <= 0.5)
                              and ((#s64 > 1.0)
                              ) or (#s1131 > 0.5)
                            ))) or (#s9 > 0.5)
                      ) or (#s8 > 0.5)
                    ) or (#s7 > 0.5)
                  ) or (#s6 > 1.5)
                ) or (#s5 > 0.5)
              ) or (#s4 > 2.5)
              and ((#s1142 <= 1.0)
                and ((#s87 <= 1.0)
                  and ((#s154 > 1.0)
                  ) or (#s87 > 1.0)
                  and ((#s4 <= 3.5)
                  )))) or (#s3 > 0.5)
            and ((#s1151 <= 1.0)
              and ((#s1152 <= 0.5)
                and ((#s1153 <= 0.5)
                  and ((#s1154 <= 0.5)
                    and ((#s1155 <= 0.5)
                      and ((#s1156 <= 0.5)
                        and ((#s1157 <= 0.5)
                          and ((#s609 <= 0.5)
                            and ((#s1159 <= 0.5)
                              and ((#s1160 <= 0.5)
                                and ((#s1161 <= 0.5)
                                  and ((#s8 <= 0.5)
                                    and ((#s1163 <= 0.5)
                                      and ((#s1164 <= 0.5)
                                        and ((#s1165 <= 0.5)
                                          and ((#s1166 <= 0.5)
                                            and ((#s1167 <= 0.5)
                                              and ((#s1168 <= 0.5)
                                                and ((#s848 <= 5.0)
                                                  and ((#s17 <= 0.5)
                                                    and ((#s35 <= 1.5)
                                                      and ((#s77 <= 1.5)
                                                        and ((#s1173 <= 1.0)
                                                          and ((#s436 <= 0.5)
                                                            and ((#s155 <= 0.5)
                                                              and ((#s808 > 0.5)
                                                                and ((#s85 > 0.5)
                                                                  and ((#s823 > 0.5)
                                                                    and ((#s154 <= 0.5)
                                                                      and ((#s67 <= 0.5)
                                                                      ))))) or (#s155 > 0.5)
                                                              and ((#s1187 > 1.5)
                                                              ))) or (#s1173 > 1.0)
                                                        ) or (#s77 > 1.5)
                                                        and ((#s1192 <= 0.5)
                                                          and ((#s1193 <= 0.5)
                                                            and ((#s88 <= 1.0)
                                                              and ((#s21 <= 1.5)
                                                                and ((#s848 <= 1.0)
                                                                  and ((#s1197 <= 2.5)
                                                                    and ((#s1198 <= 1.5)
                                                                      and ((#s158 <= 1.0)
                                                                        and ((#s851 <= 0.5)
                                                                          and ((#s34 <= 0.5)
                                                                            and ((#s42 > 0.5)
                                                                              and ((#s57 <= 0.5)
                                                                                and ((#s1205 <= 1.0)
                                                                                  and ((#s871 <= 1.0)
                                                                                    and ((#s67 <= 1.0)
                                                                                      and ((#s1208 <= 1.0)
                                                                                        and ((#s149 > 0.5)
                                                                                          and ((#s72 <= 0.5)
                                                                                            and ((#s45 > 0.5)
                                                                                            ))))))))) or (#s34 > 0.5)
                                                                            and ((#s1221 > 0.5)
                                                                            )) or (#s851 > 0.5)
                                                                          and ((#s72 <= 0.5)
                                                                            and ((#s1225 <= 0.5)
                                                                              and ((#s1226 > 0.5)
                                                                              ) or (#s1225 > 0.5)
                                                                            ) or (#s72 > 0.5)
                                                                          )) or (#s158 > 1.0)
                                                                        and ((#s144 > 0.5)
                                                                          and ((#s269 <= 0.5)
                                                                            and ((#s94 <= 2.0)
                                                                            )))) or (#s1198 > 1.5)
                                                                    ) or (#s1197 > 2.5)
                                                                    and ((#s1239 <= 1.0)
                                                                    ))) or (#s21 > 1.5)
                                                                and ((#s150 > 1.0)
                                                                  and ((#s45 > 1.0)
                                                                  )))) or (#s1193 > 0.5)
                                                          ))) or (#s35 > 1.5)
                                                      and ((#s1239 > 0.5)
                                                        and ((#s1253 <= 17.5)
                                                        ))) or (#s17 > 0.5)
                                                  ) or (#s848 > 5.0)
                                                ) or (#s1168 > 0.5)
                                              ) or (#s1167 > 0.5)
                                            ) or (#s1166 > 0.5)
                                            and ((#s868 > 0.5)
                                              and ((#s1262 > 0.5)
                                              ))) or (#s1165 > 0.5)
                                        ) or (#s1164 > 0.5)
                                      ) or (#s1163 > 0.5)
                                    ) or (#s8 > 0.5)
                                  ) or (#s1161 > 0.5)
                                ) or (#s1160 > 0.5)
                              ) or (#s1159 > 0.5)
                            ) or (#s609 > 0.5)
                            and ((#s1272 <= 0.5)
                              and ((#s35 <= 1.0)
                                and ((#s883 <= 0.5)
                                  and ((#s846 <= 0.5)
                                    and ((#s1276 <= 0.5)
                                      and ((#s1239 <= 0.5)
                                        and ((#s87 <= 0.5)
                                          and ((#s1279 <= 1.0)
                                            and ((#s57 > 0.5)
                                              and ((#s1282 > 0.5)
                                                and ((#s3 <= 1.5)
                                                )))) or (#s87 > 0.5)
                                          and ((#s64 <= 0.5)
                                            and ((#s823 > 1.0)
                                            ) or (#s64 > 0.5)
                                            and ((#s1292 > 0.5)
                                              and ((#s1294 > 2.0)
                                              )))))))) or (#s35 > 1.0)
                                and ((#s871 <= 1.0)
                                )) or (#s1272 > 0.5)
                              and ((#s42 <= 1.5)
                                and ((#s389 > 1.0)
                                  and ((#s1307 <= 0.5)
                                  )) or (#s42 > 1.5)
                                and ((#s932 > 0.5)
                                  and ((#s927 <= 59.0)
                                    and ((filesize <= 24226160.0)
                                    )))))) or (#s1157 > 0.5)
                        ) or (#s1156 > 0.5)
                      ) or (#s1155 > 0.5)
                    ) or (#s1154 > 0.5)
                  ) or (#s1153 > 0.5)
                  and ((#s1321 <= 1.5)
                    and ((#s1159 <= 0.5)
                      and ((#s1166 <= 1.0)
                        and ((#s32 <= 4.5)
                          and ((#s254 > 0.5)
                            and ((#s1327 <= 1.0)
                              and ((#s152 <= 7.5)
                                and ((#s6 <= 1.0)
                                  and ((#s1330 <= 0.5)
                                    and ((#s99 <= 3.5)
                                      and ((#s1332 <= 0.5)
                                        and ((#s89 <= 0.5)
                                          and ((#s1239 <= 0.5)
                                            and ((#s156 <= 0.5)
                                              and ((#s1336 <= 0.5)
                                                and ((#s158 <= 3.0)
                                                  and ((#s1338 <= 1.0)
                                                    and ((#s57 <= 0.5)
                                                    )) or (#s158 > 3.0)
                                                ) or (#s1336 > 0.5)
                                                and ((#s67 <= 1.0)
                                                ))) or (#s1239 > 0.5)
                                          ) or (#s89 > 0.5)
                                          and ((#s848 > 1.0)
                                            and ((#s868 > 0.5)
                                            ))) or (#s1332 > 0.5)
                                        and ((#s1292 > 0.5)
                                          and ((#s868 <= 0.5)
                                            and ((#s1292 <= 3.5)
                                              and ((#s1358 <= 0.5)
                                                or (#s1358 > 0.5)
                                                and ((#s76 <= 1.0)
                                                )))))) or (#s99 > 3.5)
                                    ) or (#s1330 > 0.5)
                                  ) or (#s6 > 1.0)
                                ) or (#s152 > 7.5)
                              ) or (#s1327 > 1.0)
                              and ((#s77 <= 3.0)
                                or (#s77 > 3.0)
                                and ((#s51 <= 1.0)
                                ))))) or (#s1166 > 1.0)
                      ) or (#s1159 > 0.5)
                    ) or (#s1321 > 1.5)
                    and ((#s1292 <= 0.5)
                      and ((#s825 <= 1.0)
                        and ((#s1379 <= 1.0)
                          and ((#s1380 <= 1.0)
                          )))))) or (#s1152 > 0.5)
                and ((#s1386 > 0.5)
                  and ((#s626 <= 3.0)
                    or (#s626 > 3.0)
                    and ((filesize > 25131176.0)
                      and ((filesize <= 25131192.0)
                      ))))) or (#s1151 > 1.0)
            )) or (#s2 > 1.5)
          and ((#s1396 <= 0.5)
            and ((#s1397 <= 0.5)
              and ((#s1398 <= 1.0)
                and ((#s1121 > 1.0)
                )) or (#s1397 > 0.5)
            ))) or (#s1 > 1.5)
        and ((#s1405 <= 0.5)
          and ((#s42 <= 1.5)
            and ((filesize <= 6348444.0)
              and ((#s1408 <= 0.5)
                and ((#s448 <= 0.5)
                  and ((#s603 <= 1.0)
                    and ((#s1411 > 1.0)
                      and ((#s1413 <= 0.5)
                        and ((#s46 <= 4.5)
                          and ((#s460 <= 0.5)
                            and ((#s265 <= 1.0)
                              and ((#s77 <= 1.0)
                                and ((filesize <= 2246636.0)
                                ))))) or (#s1413 > 0.5)
                      )) or (#s603 > 1.0)
                  ) or (#s448 > 0.5)
                ) or (#s1408 > 0.5)
              ) or (filesize > 6348444.0)
              and ((filesize <= 63029176.0)
                and ((#s495 <= 1.5)
                  and ((#s82 <= 0.5)
                    and ((#s1432 <= 7.0)
                      and ((#s75 <= 5.5)
                        and ((#s888 <= 3.0)
                          and ((#s1435 > 1.0)
                          ) or (#s888 > 3.0)
                        ))) or (#s82 > 0.5)
                  ) or (#s495 > 1.5)
                )))))) or (#s0 > 0.5)
      and ((#s1446 <= 0.5)
        and ((#s492 <= 0.5)
          and ((#s1448 <= 5.5)
            and ((#s73 <= 0.5)
              and ((#s1450 <= 3.5)
                and ((#s1451 <= 1.0)
                  and ((#s162 <= 0.5)
                    and ((#s1453 <= 0.5)
                      and ((#s1454 <= 0.5)
                        and ((#s588 <= 0.5)
                          and ((#s21 <= 0.5)
                            and ((#s87 <= 1.5)
                              and ((#s3 > 0.5)
                                and ((#s142 <= 2.5)
                                  and ((#s1461 <= 1.5)
                                    and ((#s1462 > 0.5)
                                    )))) or (#s87 > 1.5)
                              and ((#s260 <= 1.0)
                                and ((#s1468 <= 0.5)
                                  and ((#s134 <= 1.0)
                                    and ((#s69 > 0.5)
                                      and ((#s150 <= 0.5)
                                        and ((#s1473 > 1.5)
                                          and ((#s76 <= 2.0)
                                          ))))) or (#s1468 > 0.5)
                                  and ((#s50 <= 2.0)
                                    and ((#s147 <= 1.0)
                                      and ((filesize > 253136.0)
                                      )))))) or (#s21 > 0.5)
                            and ((#s1488 > 1.5)
                              and ((#s1490 <= 0.5)
                                and ((#s1491 <= 1.0)
                                  and ((#s846 <= 1.0)
                                    and ((#s1493 > 1.5)
                                    )) or (#s1491 > 1.0)
                                )))) or (#s588 > 0.5)
                          and ((#s1499 > 1.5)
                            and ((#s518 <= 1.0)
                              and ((#s1502 <= 2.0)
                              )))) or (#s1454 > 0.5)
                        and ((#s1473 <= 0.5)
                          and ((#s87 <= 0.5)
                            and ((#s848 <= 1.0)
                              and ((#s1276 <= 0.5)
                              ) or (#s848 > 1.0)
                            ) or (#s87 > 0.5)
                            and ((#s1513 <= 1.0)
                              and ((#s480 <= 0.5)
                                and ((#s134 <= 1.0)
                                  and ((#s142 > 2.5)
                                  )) or (#s480 > 0.5)
                                and ((#s1520 <= 0.5)
                                )) or (#s1513 > 1.0)
                            )) or (#s1473 > 0.5)
                          and ((#s927 <= 2.5)
                            and ((#s95 <= 37.0)
                              and ((#s254 <= 0.5)
                                and ((#s436 <= 0.5)
                                  and ((#s77 <= 1.0)
                                    and ((#s37 > 0.5)
                                    ))))) or (#s927 > 2.5)
                          ))) or (#s1453 > 0.5)
                    ) or (#s162 > 0.5)
                    and ((#s72 > 0.5)
                    )) or (#s1451 > 1.0)
                ) or (#s1450 > 3.5)
              ) or (#s73 > 0.5)
              and ((#s848 <= 1.5)
                and ((#s64 <= 1.5)
                  and ((#s1499 <= 1.5)
                    and ((#s1546 <= 1.0)
                      and ((#s16 <= 1.0)
                        and ((#s134 <= 0.5)
                          and ((#s42 <= 0.5)
                            and ((#s480 > 0.5)
                              and ((#s1552 <= 0.5)
                                and ((#s83 > 1.5)
                                ) or (#s1552 > 0.5)
                              )) or (#s42 > 0.5)
                            and ((#s1208 <= 1.0)
                              or (#s1208 > 1.0)
                              and ((#s1559 <= 1.0)
                                and ((#s1560 > 0.5)
                                ) or (#s1559 > 1.0)
                              )))) or (#s16 > 1.0)
                      ) or (#s1546 > 1.0)
                    ) or (#s1499 > 1.5)
                    and ((#s1262 <= 0.5)
                      and ((#s1568 <= 0.5)
                        and ((#s473 <= 0.5)
                          and ((#s101 <= 3.0)
                            and ((#s1571 <= 0.5)
                              and ((#s1572 <= 0.5)
                                and ((#s1573 <= 0.5)
                                  and ((#s76 <= 1.5)
                                    and ((#s155 > 0.5)
                                    ) or (#s76 > 1.5)
                                    and ((#s851 <= 0.5)
                                      and ((#s147 > 3.0)
                                        and ((filesize <= 232856.0)
                                        )) or (#s851 > 0.5)
                                    )) or (#s1573 > 0.5)
                                  and ((#s1396 <= 4.5)
                                    and ((#s147 <= 1.0)
                                    ))) or (#s1572 > 0.5)
                              ) or (#s1571 > 0.5)
                              and ((#s1591 <= 0.5)
                              )) or (#s101 > 3.0)
                            and ((#s1594 <= 3.0)
                            )) or (#s473 > 0.5)
                        ) or (#s1568 > 0.5)
                      ) or (#s1262 > 0.5)
                      and ((#s1036 <= 0.5)
                        and ((#s88 <= 3.0)
                          and ((#s1601 <= 0.5)
                            and ((#s1602 <= 1.0)
                              and ((#s135 <= 3.0)
                              ) or (#s1602 > 1.0)
                            )))))) or (#s64 > 1.5)
                  and ((#s1468 <= 0.5)
                    and ((#s1611 <= 1.5)
                      and ((#s1612 <= 2.0)
                        and ((#s1613 <= 3.5)
                          and ((#s150 <= 0.5)
                            and ((#s168 <= 1.0)
                            )) or (#s1613 > 3.5)
                          and ((#s1619 > 4.5)
                            and ((#s1379 > 0.5)
                              and ((#s1623 <= 2.5)
                              )))) or (#s1612 > 2.0)
                      ) or (#s1611 > 1.5)
                      and ((#s101 > 1.0)
                        and ((#s155 > 0.5)
                        ))) or (#s1468 > 0.5)
                    and ((#s1632 <= 0.5)
                      and ((#s1633 <= 0.5)
                        and ((#s1634 <= 0.5)
                          and ((#s99 <= 1.5)
                            or (#s99 > 1.5)
                            and ((#s1192 <= 0.5)
                              and ((#s1638 <= 1.0)
                                and ((#s1639 <= 0.5)
                                  and ((#s494 > 1.0)
                                  ))) or (#s1192 > 0.5)
                              and ((#s55 <= 0.5)
                                and ((#s1646 <= 1.0)
                                  and ((#s89 > 0.5)
                                    and ((#s1262 > 0.5)
                                      and ((#s931 <= 0.5)
                                        and ((filesize <= 17175080.0)
                                          and ((#s1653 <= 5.0)
                                            and ((#s1654 <= 0.5)
                                              or (#s1654 > 0.5)
                                              and ((#s154 <= 0.5)
                                                and ((#s1386 > 0.5)
                                                ) or (#s154 > 0.5)
                                                and ((#s969 <= 1.5)
                                                  or (#s969 > 1.5)
                                                  and ((#s95 <= 59.0)
                                                    and ((filesize <= 11259016.0)
                                                    ) or (#s95 > 59.0)
                                                  )))) or (#s1653 > 5.0)
                                          ) or (filesize > 17175080.0)
                                          and ((#s1668 > 1.0)
                                            and ((#s1670 <= 3.0)
                                              and ((filesize <= 19809960.0)
                                              ) or (#s1670 > 3.0)
                                              and ((#s95 <= 97.0)
                                                or (#s95 > 97.0)
                                                and ((#s1676 <= 0.5)
                                                ))))))))))))) or (#s1633 > 0.5)
                      )))) or (#s848 > 1.5)
                and ((#s1491 <= 1.0)
                  and ((#s94 <= 4.5)
                    and ((#s144 <= 0.5)
                      and ((#s264 <= 1.0)
                        and ((#s460 <= 0.5)
                          and ((#s868 <= 0.5)
                            and ((#s64 <= 2.0)
                              and ((#s1591 <= 0.5)
                                and ((#s0 <= 2.5)
                                  and ((#s1239 <= 0.5)
                                    and ((#s45 > 0.5)
                                      and ((#s883 > 0.5)
                                      )) or (#s1239 > 0.5)
                                    and ((#s1700 > 0.5)
                                    )) or (#s0 > 2.5)
                                  and ((#s1253 <= 1.0)
                                    and ((#s1704 > 0.5)
                                    ) or (#s1253 > 1.0)
                                  ))) or (#s64 > 2.0)
                              and ((filesize <= 1230436.0)
                                or (filesize > 1230436.0)
                                and ((#s1711 <= 0.5)
                                  and ((#s1712 <= 1.0)
                                    or (#s1712 > 1.0)
                                    and ((#s1714 > 1.0)
                                    )) or (#s1711 > 0.5)
                                ))) or (#s868 > 0.5)
                            and ((#s1718 <= 1.0)
                              and ((#s3 > 2.0)
                                and ((#s1552 <= 0.5)
                                ))))) or (#s264 > 1.0)
                        and ((#s1726 <= 4.5)
                          and ((#s26 <= 1.0)
                            and ((#s135 <= 1.0)
                              and ((#s1397 > 0.5)
                              )) or (#s26 > 1.0)
                          ) or (#s1726 > 4.5)
                        )))) or (#s1491 > 1.0)
                  and ((#s1737 <= 0.5)
                    and ((#s1738 > 1.5)
                    ) or (#s1737 > 0.5)
                  )))) or (#s1448 > 5.5)
            and ((#s1612 <= 1.0)
            )) or (#s492 > 0.5)
          and ((#s1745 <= 2.0)
            and ((#s1121 <= 1.5)
              and ((#s1700 <= 0.5)
                and ((#s1748 <= 2.0)
                  and ((#s96 <= 0.5)
                    and ((#s142 > 1.5)
                      and ((#s1153 <= 0.5)
                        and ((#s261 <= 0.5)
                          and ((#s63 <= 0.5)
                            and ((#s1613 <= 5.5)
                              and ((#s714 <= 1.0)
                                and ((#s64 <= 1.5)
                                  and ((#s1758 <= 2.0)
                                    and ((#s1759 > 1.5)
                                      and ((#s1761 <= 1.0)
                                        and ((#s851 <= 0.5)
                                          and ((#s389 > 2.0)
                                            and ((#s88 <= 1.0)
                                              and ((#s254 > 0.5)
                                                and ((#s1262 <= 0.5)
                                                  and ((#s83 <= 2.0)
                                                    and ((#s1770 <= 1.0)
                                                      and ((filesize <= 236064.0)
                                                      )))))))))))) or (#s714 > 1.0)
                              ) or (#s1613 > 5.5)
                              and ((#s191 <= 2.0)
                                and ((#s1294 > 4.5)
                                )))) or (#s261 > 0.5)
                          and ((#s155 <= 0.5)
                            and ((#s1790 > 1.5)
                              and ((#s138 > 1.0)
                              )))) or (#s1153 > 0.5)
                        and ((#s1336 > 1.0)
                          and ((#s142 > 2.5)
                            and ((#s1800 > 0.5)
                            ))))) or (#s96 > 0.5)
                    and ((#s1803 <= 1.0)
                      and ((#s138 <= 1.0)
                        and ((#s1712 > 1.5)
                          and ((#s42 <= 0.5)
                            and ((#s57 > 0.5)
                              and ((#s100 <= 0.5)
                                and ((#s925 > 0.5)
                                ))))) or (#s138 > 1.0)
                      ) or (#s1803 > 1.0)
                    )) or (#s1748 > 2.0)
                ) or (#s1700 > 0.5)
                and ((#s1819 > 0.5)
                  and ((#s1358 <= 0.5)
                    and ((#s1397 <= 1.5)
                      and ((#s254 <= 0.5)
                        and ((filesize <= 66024.0)
                          and ((#s1520 <= 0.5)
                          ) or (filesize > 66024.0)
                          and ((#s1828 <= 1.0)
                            and ((#s87 <= 1.5)
                              and ((#s1163 <= 3.0)
                                and ((#s1831 <= 0.5)
                                  and ((#s588 <= 0.5)
                                    and ((#s426 <= 1.0)
                                    ))) or (#s1163 > 3.0)
                              )))) or (#s254 > 0.5)
                        and ((#s264 <= 1.0)
                          and ((#s152 <= 6.0)
                            and ((#s99 <= 2.0)
                              and ((#s1036 <= 0.5)
                                and ((#s588 <= 0.5)
                                ) or (#s1036 > 0.5)
                              ) or (#s99 > 2.0)
                              and ((#s1711 > 2.0)
                              ))) or (#s264 > 1.0)
                        )) or (#s1397 > 1.5)
                    ) or (#s1358 > 0.5)
                  ))) or (#s1121 > 1.5)
              and ((#s1568 <= 0.5)
                and ((#s26 <= 1.0)
                  and ((#s1858 <= 0.5)
                    and ((#s41 > 0.5)
                      and ((#s462 <= 3.5)
                      )) or (#s1858 > 0.5)
                  ) or (#s26 > 1.0)
                  and ((#s1397 > 0.5)
                    and ((#s436 > 0.5)
                      and ((#s1869 <= 0.5)
                        and ((#s147 <= 1.0)
                        ))))) or (#s1568 > 0.5)
                and ((#s1874 <= 3.0)
                  and ((#s254 <= 0.5)
                  )))) or (#s1745 > 2.0)
          )) or (#s1446 > 0.5)
        and ((#s1880 <= 0.5)
          and ((#s1050 <= 0.5)
            and ((#s1338 <= 1.5)
              and ((#s1153 <= 1.5)
                and ((#s1282 <= 0.5)
                  and ((#s1711 <= 0.5)
                    and ((#s1043 > 0.5)
                      and ((#s588 <= 2.5)
                        and ((#s1332 <= 0.5)
                          and ((#s1890 <= 0.5)
                            and ((#s1891 > 1.5)
                              and ((#s465 > 0.5)
                                and ((#s75 <= 1.0)
                                  and ((#s492 > 1.0)
                                    and ((filesize > 541744.0)
                                    ))))) or (#s1890 > 0.5)
                          )))) or (#s1711 > 0.5)
                    and ((#s1573 > 0.5)
                    )) or (#s1282 > 0.5)
                  and ((#s1380 <= 0.5)
                    and ((#s1759 <= 1.5)
                      and ((#s492 > 0.5)
                        and ((#s87 > 1.0)
                          and ((#s1638 > 1.0)
                          )))) or (#s1380 > 0.5)
                  )) or (#s1153 > 1.5)
              ) or (#s1338 > 1.5)
              and ((#s1920 > 1.5)
              ))) or (#s1880 > 0.5)
          and ((#s1924 <= 0.5)
            and ((#s1192 <= 1.5)
              and ((#s1800 <= 0.5)
                and ((#s1490 <= 1.0)
                  and ((#s1358 <= 0.5)
                    and ((#s64 > 0.5)
                      and ((#s1700 > 0.5)
                      )) or (#s1358 > 0.5)
                  ))))))))
}